// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test/unsafekzg"
)

// In this example we show how to use PLONK with KZG commitments for BLS12-381 pairing check.
// The circuit verifies e(P1, Q1) * e(P2, Q2) == 1 using emulated arithmetic.

// Circuit for BLS12-381 pairing check using emulated arithmetic
type Circuit struct {
	In1G1 sw_bls12381.G1Affine
	In2G1 sw_bls12381.G1Affine
	In1G2 sw_bls12381.G2Affine
	In2G2 sw_bls12381.G2Affine
}

// Define declares the circuit's constraints
// Verifies e(In1G1, In1G2) * e(In2G1, In2G2) == 1
func (circuit *Circuit) Define(api frontend.API) error {

	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	return pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&circuit.In1G1, &circuit.In2G1},
		[]*sw_bls12381.G2Affine{&circuit.In1G2, &circuit.In2G2},
	)
}

func randomG1G2Affines() (bls12381.G1Affine, bls12381.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s1, _ := rand.Int(rand.Reader, mod)
	s2, _ := rand.Int(rand.Reader, mod)
	var p bls12381.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls12381.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

func main() {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	// create the necessary data for KZG.
	// This is a toy example, normally the trusted setup to build ZKG
	// has been run before.
	// The size of the data in KZG should be the closest power of 2 bounding //
	// above max(nbConstraints, nbVariables).
	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		panic(err)
	}

	// Generate test data: e(a,2b) * e(-2a,b) == 1
	p1, q1 := randomG1G2Affines()
	var p2 bls12381.G1Affine
	p2.Double(&p1).Neg(&p2)
	var q2 bls12381.G2Affine
	q2.Set(&q1)
	q1.Double(&q1)

	// Witnesses instantiation. Witness is known only by the prover,
	// while public w is a public data known by the verifier.
	var w Circuit
	w.In1G1 = sw_bls12381.NewG1Affine(p1)
	w.In1G2 = sw_bls12381.NewG2Affine(q1)
	w.In2G1 = sw_bls12381.NewG1Affine(p2)
	w.In2G2 = sw_bls12381.NewG2Affine(q2)

	witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}

	// public data consists of the polynomials describing the constants involved
	// in the constraints, the polynomial describing the permutation ("grand
	// product argument"), and the FFT domains.
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	//_, err := plonk.Setup(r1cs, kate, &publicWitness)
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
	_, err = proof.WriteTo(&buf)
	if err != nil {
		panic(fmt.Sprintf("failed to serialize proof: %v", err))
	}
	proofSize := buf.Len()
	fmt.Printf("Prove generation time: %v\n", proveTime)
	fmt.Printf("Proof size: %d bytes\n", proofSize)

	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
}
