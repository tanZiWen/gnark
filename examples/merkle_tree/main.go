package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test/unsafekzg"
)

// MerkleProofTest 用于测试的Merkle证明电路
type MerkleProofTest struct {
	M    merkle.MerkleProof `gnark:",private"`
	Leaf frontend.Variable  `gnark:",private"`
}

func (mp *MerkleProofTest) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProof(api, &h, mp.Leaf)
	return nil
}

func main() {
	fmt.Println("=== Merkle 证明完整演示 ===")

	// 使用简单的参数开始
	numLeaves := 8
	depth := 3

	fmt.Printf("配置参数:\n")
	fmt.Printf("  叶子数量: %d\n", numLeaves)
	fmt.Printf("  树深度: %d\n", depth)
	fmt.Printf("  哈希函数: MIMC_BN254\n")

	// 第一步：编译电路
	fmt.Println("\n--- 步骤 1: 编译电路 ---")
	var circuit MerkleProofTest
	circuit.M.Path = make([]frontend.Variable, depth+1)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal("编译失败:", err)
	}
	fmt.Printf("✓ 电路编译成功，约束数: %d\n", ccs.GetNbConstraints())

	// 第二步：生成可信设置
	fmt.Println("\n--- 步骤 2: 生成可信设置 ---")
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		log.Fatal("SRS生成失败:", err)
	}

	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		log.Fatal("Setup失败:", err)
	}
	fmt.Println("✓ 可信设置完成")

	// 第三步：生成测试数据
	fmt.Println("\n--- 步骤 3: 生成测试数据 ---")
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())
	log.Printf("模数字节数: %d\n", modNbBytes)
	// 生成确定性的简单数据便于调试
	fmt.Println("生成叶子节点:")
	testValues := make([]*big.Int, numLeaves)
	var buf bytes.Buffer
	min := hash.MIMC_BN254.New()
	for i := 0; i < numLeaves; i++ {
		// 使用简单的递增值
		testValues[i] = big.NewInt(int64((i + 1) * 1000))
		min.Write(testValues[i].Bytes())
		buf.Write(min.Sum([]byte{}))
	}

	// 第四步：测试多个叶子的证明
	fmt.Println("\n--- 步骤 4: 生成和验证 Merkle 证明 ---")
	testIndices := []uint64{0, 1, 3, 7}

	for i, targetIndex := range testIndices {
		fmt.Printf("\n=== 测试 %d/%d: 叶子索引 %d ===\n", i+1, len(testIndices), targetIndex)

		// 重置buffer指针
		bufCopy := bytes.NewBuffer(buf.Bytes())

		// 生成Merkle证明
		fmt.Printf("为叶子 %d (值: %v) 生成 Merkle 证明...\n", targetIndex, testValues[targetIndex])
		hGo := hash.MIMC_BN254.New()
		merkleRoot, proofPath, numLeavesResult, err := merkletree.BuildReaderProof(bufCopy, hGo, modNbBytes, targetIndex)
		if err != nil {
			log.Printf("构建证明失败 (索引 %d): %v", targetIndex, err)
			continue
		}

		fmt.Printf("  Merkle根: %v\n", merkleRoot)
		fmt.Printf("  返回的叶子数: %d\n", numLeavesResult)
		fmt.Printf("  证明路径长度: %d\n", len(proofPath))

		// 打印证明路径
		for j, pathElement := range proofPath {
			fmt.Printf("    路径[%d]: %v\n", j, pathElement)
		}

		// 在Go中验证证明
		verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, targetIndex, numLeavesResult)
		if !verified {
			log.Printf("Go验证失败 (索引 %d)", targetIndex)
			continue
		}
		fmt.Println("  ✓ Go中的Merkle证明验证通过")

		// 检查路径长度是否匹配
		if len(proofPath) != depth+1 {
			log.Printf("路径长度不匹配 (索引 %d): 期望 %d, 实际 %d", targetIndex, depth+1, len(proofPath))
			continue
		}

		// 创建witness
		fmt.Println("  创建零知识证明witness...")
		var witness MerkleProofTest
		witness.Leaf = targetIndex // 使用索引作为叶子值
		witness.M.RootHash = merkleRoot
		witness.M.Path = make([]frontend.Variable, len(proofPath))

		for j := 0; j < len(proofPath); j++ {
			witness.M.Path[j] = proofPath[j]
		}
		log.Printf("创建witness成功 (索引 %d), RootHash: %v, Path: %v", targetIndex, witness.M.RootHash, witness.M.Path)
		// 生成零知识证明
		fmt.Println("  生成零知识证明...")
		w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			log.Printf("创建witness失败 (索引 %d): %v", targetIndex, err)
			continue
		}

		proof, err := native_plonk.Prove(ccs, pk, w)
		if err != nil {
			log.Printf("证明生成失败 (索引 %d): %v", targetIndex, err)
			continue
		}

		// 验证零知识证明
		fmt.Println("  验证零知识证明...")
		pubWitness, err := w.Public()
		if err != nil {
			log.Printf("提取公共witness失败 (索引 %d): %v", targetIndex, err)
			continue
		}

		err = native_plonk.Verify(proof, vk, pubWitness)
		if err != nil {
			log.Printf("证明验证失败 (索引 %d): %v", targetIndex, err)
			continue
		}

		fmt.Printf("  ✓ 零知识证明生成和验证成功！\n")
		fmt.Printf("  ✓ 成功证明叶子 %d (值: %v) 存在于 Merkle 树中\n", targetIndex, testValues[targetIndex])
	}

	// // 第五步：随机数据测试
	// fmt.Println("\n--- 步骤 5: 随机数据测试 ---")
	// testRandomData(ccs, pk, vk, depth, modNbBytes)

	// fmt.Println("\n=== 测试完成 ===")
	// fmt.Println("🎉 Merkle 证明演示成功完成！")
	// fmt.Println("✅ 验证了多个叶子节点的存在性")
	// fmt.Println("✅ 零知识证明保护了其他叶子的隐私")
	// fmt.Println("✅ 验证者只需要知道 Merkle 根，无需了解具体内容")
}

func testRandomData(ccs constraint.ConstraintSystem, pk native_plonk.ProvingKey, vk native_plonk.VerifyingKey, depth int, modNbBytes int) {
	fmt.Println("使用随机数据测试...")

	numLeaves := 8
	mod := ecc.BN254.ScalarField()

	// 生成随机测试数据
	var buf bytes.Buffer
	for i := 0; i < numLeaves; i++ {
		leaf, err := rand.Int(rand.Reader, mod)
		if err != nil {
			log.Printf("生成随机数失败: %v", err)
			return
		}

		b := leaf.Bytes()
		padded := make([]byte, modNbBytes)
		copy(padded[modNbBytes-len(b):], b)
		buf.Write(padded)
	}

	// 测试一个随机索引
	targetIndex := uint64(3)
	fmt.Printf("测试随机数据中的叶子索引: %d\n", targetIndex)

	// 生成证明
	hGo := hash.MIMC_BN254.New()
	merkleRoot, proofPath, numLeavesResult, err := merkletree.BuildReaderProof(&buf, hGo, modNbBytes, targetIndex)
	if err != nil {
		log.Printf("随机数据证明构建失败: %v", err)
		return
	}

	// Go验证
	verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, targetIndex, numLeavesResult)
	if !verified {
		log.Printf("随机数据Go验证失败")
		return
	}
	fmt.Println("✓ 随机数据Go验证通过")

	// 检查路径长度
	if len(proofPath) != depth+1 {
		log.Printf("随机数据路径长度错误: 期望 %d, 实际 %d", depth+1, len(proofPath))
		return
	}

	// 创建witness并生成ZK证明
	var witness MerkleProofTest
	witness.Leaf = targetIndex
	witness.M.RootHash = merkleRoot
	witness.M.Path = make([]frontend.Variable, len(proofPath))

	for i := 0; i < len(proofPath); i++ {
		witness.M.Path[i] = proofPath[i]
	}

	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		log.Printf("随机数据创建witness失败: %v", err)
		return
	}

	proof, err := native_plonk.Prove(ccs, pk, w)
	if err != nil {
		log.Printf("随机数据证明生成失败: %v", err)
		return
	}

	pubWitness, err := w.Public()
	if err != nil {
		log.Printf("随机数据提取公共witness失败: %v", err)
		return
	}

	err = native_plonk.Verify(proof, vk, pubWitness)
	if err != nil {
		log.Printf("随机数据证明验证失败: %v", err)
		return
	}

	fmt.Println("✓ 随机数据零知识证明成功！")
}
