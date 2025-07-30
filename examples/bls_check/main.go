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
	"github.com/consensys/gnark/test/unsafekzg"
	blst "github.com/supranational/blst/bindings/go"
)

// BLSSignatureCircuit 定义 BLS 签名验证电路
type BLSSignatureCircuit struct {
	Signature   sw_bls12381.G2Affine // 签名 σ ∈ G2
	PubKey      sw_bls12381.G1Affine // 公钥 PK ∈ G1
	MessageHash sw_bls12381.G2Affine // 消息哈希 H(m) ∈ G2

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

	// 验证配对等式：e(Signature, G2Gen) == e(MessageHash, PubKey)
	err = pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.PubKey, &oneG1},            // G1 点 (生成元和公钥)
		[]*sw_bls12381.G2Affine{&c.MessageHash, &c.Signature}, // G2 点 (签名和消息哈希)
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

	var msgG2Point bls12381.G2Affine
	msgHash := blst.HashToG2(msg, dst)
	if _, err := msgG2Point.SetBytes(msgHash.Serialize()); err != nil {
		log.Fatal("Failed to decode msgG2Point point from compressed bytes: ", err)
	}

	hash, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		log.Fatal("Failed to hash message to G2: ", err)
	}

	// 获取 G2 生成元
	_, _, g1gen, _ := bls12381.Generators()
	g1gen.Neg(&g1gen)
	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{pkG1Point, g1gen}, []bls12381.G2Affine{hash, sigG2Point})
	if !ok {
		log.Fatal("Pairing does not match, constraint will fail. err:%v", err)
	}

	var circuit BLSSignatureCircuit

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

	var w = BLSSignatureCircuit{
		Signature:   sw_bls12381.NewG2Affine(sigG2Point),
		PubKey:      sw_bls12381.NewG1Affine(pkG1Point),
		MessageHash: sw_bls12381.NewG2Affine(msgG2Point),
		G1Gen:       sw_bls12381.NewG1Affine(g1gen),
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
		log.Fatal(err)
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
