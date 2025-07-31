package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/consensys/gnark/test/unsafekzg"
	blst "github.com/supranational/blst/bindings/go"
)

// BLSSignatureCircuit 定义 BLS 签名验证电路
type BLSSignatureCircuit struct {
	Signature sw_bls12381.G2Affine // 签名 σ ∈ G2
	PubKey1   sw_bls12381.G1Affine // 公钥 PK ∈ G1
	PubKey2   sw_bls12381.G1Affine // 公钥 PK ∈ G1
	Message   sw_bls12381.G2Affine // 消息哈希 H(m) ∈ G2
	Msg       []uints.U8           // 消息内容
	PublicKey sw_bls12381.G1Affine // 公钥 PK ∈ G1
}

// Define 定义电路约束
func (c *BLSSignatureCircuit) Define(api frontend.API) error {
	_, _, g1gen, _ := bls12381.Generators()
	g1gen.Neg(&g1gen)
	oneG1 := sw_bls12381.NewG1Affine(g1gen)
	// 初始化配对计算对象
	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return fmt.Errorf("sw_emulated New: %v", err)
	}

	aggregatedPK := curve.AddUnified(&c.PubKey1, &c.PubKey2)

	// 3. 验证聚合的公钥等于公开的聚合公钥
	curve.AssertIsEqual(aggregatedPK, &c.PublicKey)

	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return fmt.Errorf("sw_bls12381 NewG2: %w", err)
	}
	hash, err := g2.HashToG2(api, c.Msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"))
	if err != nil {
		return fmt.Errorf("HashToG2: %w", err)
	}

	g2.AssertIsEqual(hash, &c.Message)

	//验证配对等式：e(Signature, G2Gen) == e(MessageHash, PubKey)
	err = pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.PublicKey, &oneG1},     // G1 点 (生成元和公钥)
		[]*sw_bls12381.G2Affine{&c.Message, &c.Signature}, // G2 点 (签名和消息哈希)
	)
	if err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}

	return nil
}

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

func main() {

	var ikm [32]byte
	_, _ = rand.Read(ikm[:])
	sk := blst.KeyGen(ikm[:])
	pk2 := new(PublicKey).From(sk)

	_, _ = rand.Read(ikm[:])
	sk1 := blst.KeyGen(ikm[:])
	pk1 := new(PublicKey).From(sk1)

	var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	msg := []byte("hello foo")
	log.Println("msg len:", len(msg))
	sig := new(Signature).Sign(sk, msg, dst, true)
	if sig == nil {
		log.Fatal("Failed to generate signature with HashToG2")
	}
	sig1 := new(Signature).Sign(sk1, msg, dst, true)
	if sig1 == nil {
		log.Fatal("Failed to generate signature with HashToG2")
	}
	var aggpk = new(AggregatePublicKey)
	aggpk.Aggregate([]*PublicKey{pk2, pk1}, true)
	var aggsig = new(AggregateSignature)
	aggsig.Aggregate([]*Signature{sig, sig1}, true)

	if !sig.Verify(true, pk2, true, msg, dst) {
		fmt.Println("ERROR: sig Invalid!")
	} else {
		fmt.Println("Valid!")
	}

	if !sig1.Verify(true, pk1, true, msg, dst) {
		fmt.Println("ERROR: sig1 Invalid!")
	} else {
		fmt.Println("Valid!")
	}

	var aggSigAffine = aggsig.ToAffine()
	var aggpkAffine = aggpk.ToAffine()
	if !aggSigAffine.Verify(true, aggpkAffine, true, msg, dst) {
		fmt.Println("ERROR: agSig Invalid!")
	} else {
		fmt.Println("Valid!")
	}

	var sigG2Point bls12381.G2Affine
	serialized := aggSigAffine.Serialize()
	if len(serialized) != 192 {
		log.Fatal("Serialized G2 point should be 192 bytes, got: ", len(serialized))
	}
	if _, err := sigG2Point.SetBytes(serialized); err != nil {
		log.Fatal("Failed to decode g2Point point from compressed bytes: ", err)
	}
	var pkG1Point bls12381.G1Affine
	if len(aggpkAffine.Serialize()) != 96 {
		log.Fatal("Serialized G1 point should be 96 bytes, got: ", len(aggpkAffine.Serialize()))
	}
	if _, err := pkG1Point.SetBytes(aggpkAffine.Serialize()); err != nil {
		log.Fatal("Failed to decode g1Point point from compressed bytes: ", err)
	}

	var pk2G1 bls12381.G1Affine
	if len(pk2.Serialize()) != 96 {
		log.Fatal("Serialized G1 point should be 96 bytes, got: ", len(pk2.Serialize()))
	}
	if _, err := pk2G1.SetBytes(pk2.Serialize()); err != nil {
		log.Fatal("Failed to decode g1Point point from compressed bytes: ", err)
	}

	var pk1G1 bls12381.G1Affine
	if len(pk1.Serialize()) != 96 {
		log.Fatal("Serialized G1 point should be 96 bytes, got: ", len(pk1.Serialize()))
	}
	if _, err := pk1G1.SetBytes(pk1.Serialize()); err != nil {
		log.Fatal("Failed to decode g1Point point from compressed bytes: ", err)
	}

	var msgG2Point bls12381.G2Affine
	msgHash := blst.HashToG2(msg, dst)
	if _, err := msgG2Point.SetBytes(msgHash.Serialize()); err != nil {
		log.Fatal("Failed to decode msgG2Point point from compressed bytes: ", err)
	}

	// msg1 := []byte("hello")
	hash, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		log.Fatal("Failed to hash message to G2: ", err)
	}
	fmt.Printf("HashToG2 bytes len: %v\n", len(hash.Bytes()))
	// 获取 G2 生成元
	_, _, g1gen, _ := bls12381.Generators()
	g1gen.Neg(&g1gen)
	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{pkG1Point, g1gen}, []bls12381.G2Affine{hash, sigG2Point})
	if !ok {
		log.Fatal("Pairing does not match, constraint will fail. err:%v", err)
	} else {
		fmt.Println("Pairing check passed!")
	}

	var acc bls12381.G1Jac
	acc.FromAffine(&pk1G1)
	var pk1G1Jac bls12381.G1Jac
	pk1G1Jac.FromAffine(&pk2G1)
	acc.AddAssign(&pk1G1Jac)

	var result bls12381.G1Affine
	result.FromJacobian(&acc)

	if !result.Equal(&pkG1Point) {
		log.Fatal("Public key aggregation failed, expected: ", pkG1Point, " got: ", result)
	} else {
		fmt.Println("Public key aggregation successful!")
	}

	var circuit BLSSignatureCircuit
	circuit.Msg = make([]uints.U8, len(msg))
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// Setup PLONK
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	data := make([]uints.U8, len(msg))
	for i := 0; i < len(data); i++ {
		data[i] = uints.NewU8(msg[i])
	}

	var w = BLSSignatureCircuit{
		Signature: sw_bls12381.NewG2Affine(sigG2Point),
		PubKey1:   sw_bls12381.NewG1Affine(pk2G1),
		PubKey2:   sw_bls12381.NewG1Affine(pk1G1),
		Message:   sw_bls12381.NewG2Affine(msgG2Point),
		PublicKey: sw_bls12381.NewG1Affine(pkG1Point),
		Msg:       data,
	}

	witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	// Prove and verify
	startTime := time.Now()

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal("plonk.Prove:%v", err)
	}

	proveTime := time.Since(startTime)
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
	}
	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		panic(fmt.Sprintf("failed to serialize proof: %v", err))
	}
	proofSize := buf.Len()
	fmt.Printf("Prove generation time: %v\n", proveTime)
	fmt.Printf("Proof size: %d bytes\n", proofSize)

	// 目标文件名
	filename := "proof.txt"

	// 方法 1：使用 os.Create 和 buf.WriteTo
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close() // 确保文件关闭

	// 将 buf 内容写入文件
	_, err = proof.WriteTo(file)
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}
	fmt.Println("成功写入文件:", filename)

	buf.Reset()
	_, err = vk.WriteRawTo(&buf)
	if err != nil {
		panic(fmt.Sprintf("failed to serialize verification key: %v", err))
	}
	// 将验证密钥写入文件
	vkFile, err := os.Create("vk.txt")
	if err != nil {
		fmt.Println("创建验证密钥文件失败:", err)
		return
	}
	defer vkFile.Close() // 确保文件关闭

	_, err = buf.WriteTo(vkFile)
	if err != nil {
		fmt.Println("写入验证密钥文件失败:", err)
		return
	}
	fmt.Println("成功写入验证密钥文件: vk.txt")

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}

}
