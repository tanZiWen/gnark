package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test/unsafekzg"
)

var (
	BLSDomain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_xxxxxxxx")
)

type hashToG2Circuit struct {
	Msg []uints.U8
	Res sw_bls12381.G2Affine
}

func (c *hashToG2Circuit) Define(api frontend.API) error {
	g2, err := sw_bls12381.NewG2(api)
	if err != nil {
		return err
	}
	res, e := g2.HashToG2(api, c.Msg, BLSDomain)
	if e != nil {
		return e
	}
	g2.AssertIsEqual(res, &c.Res)
	return nil
}

func main() {
	fmt.Println("1")
	msg := []byte("Hello, World!")
	if len(msg) != 13 {
		log.Fatalf("Msg length must be 13 bytes, got %d", len(msg))
	}
	hash, err := bls12381.HashToG2(msg, BLSDomain)
	if err != nil {
		log.Fatal("Failed to hash message to G2: ", err)
	}
	testdata := make([]uints.U8, len(msg))
	for i := 0; i < len(testdata); i++ {
		testdata[i] = uints.NewU8(msg[i])
	}
	w := hashToG2Circuit{
		Msg: testdata,
		Res: sw_bls12381.NewG2Affine(hash),
	}
	circuit := hashToG2Circuit{
		Msg: make([]uints.U8, len(msg)),
		Res: sw_bls12381.NewG2Affine(hash),
	}
	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	//_, err := plonk.Setup(r1cs, kate, &publicWitness)
	if err != nil {
		log.Fatal(err)
	}
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}
	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}
