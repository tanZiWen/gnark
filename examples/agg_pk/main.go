package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	// prove that P*Q == N
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	// we must also enforce that P != 1 and Q != 1
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNative{})
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, plonk.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        plonk.Proof[FR, G1El, G2El]
	VerifyingKey plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	InnerWitness plonk.Witness[FR]                  `gnark:",public"`
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func main() {
	// compute the proof which we want to verify recursively
	// 使用 BLS12-381 作为内部和外部曲线
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(
		ecc.BLS12_381.ScalarField(), ecc.BLS12_381.ScalarField(),
	)

	// initialize the witness elements
	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12381.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12381.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &OuterCircuit[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	fmt.Println("递归证明验证成功！")
}
