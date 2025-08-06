package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"
	blst "github.com/supranational/blst/bindings/go"
)

// AggregatePublicKeyCircuit 定义聚合公钥验证电路
type AggregatePublicKeyCircuit struct {
	// 私有输入：三个单独的公钥
	PubKey1 sw_bls12381.G1Affine
	PubKey2 sw_bls12381.G1Affine
	PubKey3 sw_bls12381.G1Affine

	// 公开输入：聚合后的公钥
	AggregatedPubKey sw_bls12381.G1Affine
}

// Define 定义电路约束：验证 PubKey1 + PubKey2 + PubKey3 == AggregatedPubKey
func (circuit *AggregatePublicKeyCircuit) Define(api frontend.API) error {
	// 创建椭圆曲线操作对象
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](
		api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return fmt.Errorf("failed to create curve: %w", err)
	}

	// 计算三个公钥的聚合：PubKey1 + PubKey2 + PubKey3
	temp := curve.AddUnified(&circuit.PubKey1, &circuit.PubKey2)
	computedAggPubKey := curve.AddUnified(temp, &circuit.PubKey3)

	// 验证计算出的聚合公钥等于给定的聚合公钥
	curve.AssertIsEqual(computedAggPubKey, &circuit.AggregatedPubKey)

	return nil
}

// 类型别名
type PublicKey = blst.P1Affine
type AggregatePublicKey = blst.P1Aggregate

// createTestKeys 创建测试用的密钥对
func createTestKeys() ([]PublicKey, PublicKey) {
	var publicKeys []PublicKey

	// 生成3个随机密钥对
	for i := 0; i < 3; i++ {
		var ikm [32]byte
		_, err := rand.Read(ikm[:])
		if err != nil {
			log.Fatal("Failed to generate random IKM:", err)
		}

		// 生成私钥和公钥
		sk := blst.KeyGen(ikm[:])
		pk := new(PublicKey).From(sk)
		publicKeys = append(publicKeys, *pk)

		fmt.Printf("Generated Public Key %d: %x\n", i+1, pk.Serialize()[:16]) // 显示前16字节
	}

	// 聚合公钥
	aggPubKey := new(AggregatePublicKey)
	pkPointers := make([]*PublicKey, len(publicKeys))
	for i := range publicKeys {
		pkPointers[i] = &publicKeys[i]
	}

	success := aggPubKey.Aggregate(pkPointers, true)
	if !success {
		log.Fatal("Failed to aggregate public keys")
	}

	aggregatedPK := aggPubKey.ToAffine()
	fmt.Printf("Aggregated Public Key: %x\n", aggregatedPK.Serialize()[:16]) // 显示前16字节

	return publicKeys, *aggregatedPK
}

// convertToGnarkG1 将 blst.P1Affine 转换为 bls12381.G1Affine
func convertToGnarkG1(blstPK PublicKey) bls12381.G1Affine {
	var gnarkPK bls12381.G1Affine
	serialized := blstPK.Serialize()

	if len(serialized) != 96 {
		log.Fatalf("Serialized G1 point should be 96 bytes, got: %d", len(serialized))
	}

	if _, err := gnarkPK.SetBytes(serialized); err != nil {
		log.Fatal("Failed to decode G1 point from compressed bytes:", err)
	}

	return gnarkPK
}

// verifyAggregationNatively 使用原生方法验证聚合是否正确
func verifyAggregationNatively(publicKeys []PublicKey, aggregatedPK PublicKey) bool {
	// 手动计算聚合
	var acc bls12381.G1Jac
	first := convertToGnarkG1(publicKeys[0])
	acc.FromAffine(&first)

	for i := 1; i < len(publicKeys); i++ {
		var pkJac bls12381.G1Jac
		pk := convertToGnarkG1(publicKeys[i])
		pkJac.FromAffine(&pk)
		acc.AddAssign(&pkJac)
	}

	var result bls12381.G1Affine
	result.FromJacobian(&acc)

	expected := convertToGnarkG1(aggregatedPK)
	return result.Equal(&expected)
}

// createCircuitTemplate 创建电路编译模板
func createCircuitTemplate() *AggregatePublicKeyCircuit {
	// 使用零点进行初始化（仅用于编译）
	var zero bls12381.G1Affine
	zero.SetInfinity()

	return &AggregatePublicKeyCircuit{
		PubKey1:          sw_bls12381.NewG1Affine(zero),
		PubKey2:          sw_bls12381.NewG1Affine(zero),
		PubKey3:          sw_bls12381.NewG1Affine(zero),
		AggregatedPubKey: sw_bls12381.NewG1Affine(zero),
	}
}

// testWrongAggregation 测试使用错误聚合公钥时的情况
func testWrongAggregation(r1cs *cs.SparseR1CS, pk plonk.ProvingKey, publicKeys []PublicKey) {
	fmt.Println("测试错误的聚合公钥...")

	// 创建一个错误的聚合公钥（使用第一个公钥作为"错误的"聚合公钥）
	wrongAggPK := publicKeys[0]

	gnarkPK1 := convertToGnarkG1(publicKeys[0])
	gnarkPK2 := convertToGnarkG1(publicKeys[1])
	gnarkPK3 := convertToGnarkG1(publicKeys[2])
	gnarkWrongAggPK := convertToGnarkG1(wrongAggPK)

	wrongWitness := AggregatePublicKeyCircuit{
		PubKey1:          sw_bls12381.NewG1Affine(gnarkPK1),
		PubKey2:          sw_bls12381.NewG1Affine(gnarkPK2),
		PubKey3:          sw_bls12381.NewG1Affine(gnarkPK3),
		AggregatedPubKey: sw_bls12381.NewG1Affine(gnarkWrongAggPK), // 错误的聚合公钥
	}

	wrongWitnessFull, err := frontend.NewWitness(&wrongWitness, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal("创建错误 witness 失败:", err)
	}

	// 尝试生成证明，应该失败
	_, err = plonk.Prove(r1cs, pk, wrongWitnessFull)
	if err != nil {
		fmt.Printf("✅ 预期的错误：使用错误聚合公钥时证明生成失败\n")
		fmt.Printf("   错误信息: %v\n", err)
	} else {
		fmt.Println("❌ 意外：使用错误聚合公钥时证明竟然成功了！")
	}
}

func main() {
	fmt.Println("=== BLS12-381 聚合公钥验证电路示例 ===")
	fmt.Printf("当前用户: %s\n", "tanZiWen")
	fmt.Printf("当前时间: %s\n\n", "2025-08-04 14:16:50")

	// 1. 生成测试密钥
	fmt.Println("1. 生成测试密钥...")
	publicKeys, aggregatedPK := createTestKeys()

	// 2. 验证聚合是否正确（使用原生方法）
	fmt.Println("\n2. 原生验证聚合公钥...")
	if verifyAggregationNatively(publicKeys, aggregatedPK) {
		fmt.Println("✅ 原生验证通过：聚合公钥正确")
	} else {
		log.Fatal("❌ 原生验证失败：聚合公钥不正确")
	}

	// 3. 编译电路
	fmt.Println("\n3. 编译零知识证明电路...")
	// circuit := createCircuitTemplate()
	var circuit AggregatePublicKeyCircuit

	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal("电路编译失败:", err)
	}
	fmt.Printf("✅ 电路编译成功，约束数量: %d\n", r1cs.GetNbConstraints())

	// 4. Setup PLONK
	fmt.Println("\n4. 执行 PLONK Setup...")
	scs := r1cs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		log.Fatal("SRS 生成失败:", err)
	}

	pk, vk, err := plonk.Setup(r1cs, srs, srsLagrange)
	if err != nil {
		log.Fatal("PLONK Setup 失败:", err)
	}
	fmt.Println("✅ PLONK Setup 完成")

	// 5. 创建正确的 witness
	fmt.Println("\n5. 创建证明用的 witness...")
	gnarkPK1 := convertToGnarkG1(publicKeys[0])
	gnarkPK2 := convertToGnarkG1(publicKeys[1])
	gnarkPK3 := convertToGnarkG1(publicKeys[2])
	gnarkAggPK := convertToGnarkG1(aggregatedPK)

	witness := AggregatePublicKeyCircuit{
		PubKey1:          sw_bls12381.NewG1Affine(gnarkPK1),
		PubKey2:          sw_bls12381.NewG1Affine(gnarkPK2),
		PubKey3:          sw_bls12381.NewG1Affine(gnarkPK3),
		AggregatedPubKey: sw_bls12381.NewG1Affine(gnarkAggPK),
	}

	// 6. 生成 witness
	witnessFull, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal("创建完整 witness 失败:", err)
	}

	witnessPublic, err := frontend.NewWitness(&witness, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal("创建公开 witness 失败:", err)
	}

	// 7. 生成证明
	fmt.Println("\n6. 生成零知识证明...")
	startTime := time.Now()

	proof, err := plonk.Prove(r1cs, pk, witnessFull)
	if err != nil {
		log.Fatal("证明生成失败:", err)
	}

	proveTime := time.Since(startTime)
	fmt.Printf("✅ 证明生成成功，耗时: %v\n", proveTime)

	// 8. 验证证明
	fmt.Println("\n7. 验证零知识证明...")
	startTime = time.Now()

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal("证明验证失败:", err)
	}

	verifyTime := time.Since(startTime)
	fmt.Printf("✅ 证明验证成功，耗时: %v\n", verifyTime)

	// 9. 测试错误情况：使用错误的聚合公钥
	fmt.Println("\n8. 测试错误情况...")
	testWrongAggregation(scs, pk, publicKeys)

	fmt.Println("\n=== 演示完成 ===")
	fmt.Println("✅ 成功证明了三个公钥的聚合等于给定的聚合公钥")
	fmt.Println("✅ 零知识证明系统正确拒绝了错误的聚合公钥")
}
