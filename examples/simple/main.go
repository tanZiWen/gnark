package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	cryptoeddsa "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	hashminc "github.com/consensys/gnark/std/hash/mimc"
	stdeddsa "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test/unsafekzg"
)

type AccountCircuit struct {
	PublicKey stdeddsa.PublicKey `gnark:",public"`
	Signature stdeddsa.Signature `gnark:",public"`
	Message   frontend.Variable  `gnark:",public"`
}

func (circuit *AccountCircuit) Define(api frontend.API) error {

	// Initialize MiMC hash function in the circuit
	hFunc, err := hashminc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("failed to initialize MiMC: %v", err)
	}

	curve, err := twistededwards.NewEdCurve(api, tedwards.BLS12_381)
	if err != nil {
		return fmt.Errorf("failed to initialize curve: %v", err)
	}

	// Verify EDDSA signature in the circuit
	err = stdeddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &hFunc)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	}
	return nil
}

func main() {
	// Compile the circuit
	var circuit AccountCircuit
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

	// Generate EDDSA key pair and signature
	pkey, err := cryptoeddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	message := []byte("message")
	hFunc := mimc.NewMiMC()
	hFunc.Write(message)
	msgHash := hFunc.Sum([]byte{}) // Compute MiMC hash of the message
	var msgHashFr fr.Element
	msgHashFr.SetBytes(msgHash[:]) // Convert [32]uint8 to []byte using slice
	sigBytes, err := pkey.Sign(msgHash, hFunc)
	if err != nil {
		panic(err)
	}
	var sig cryptoeddsa.Signature
	if _, err := sig.SetBytes(sigBytes); err != nil {
		panic(err)
	}
	hFuncVerify := mimc.NewMiMC()
	_, err = pkey.PublicKey.Verify(sigBytes, []byte{}, hFuncVerify)
	if err != nil {
		panic("signature verification failed outside circuit")
	}
	var s fr.Element
	s.SetBytes(sig.S[:])
	// Create witness
	assignment := AccountCircuit{
		PublicKey: stdeddsa.PublicKey{
			A: twistededwards.Point{X: pkey.PublicKey.A.X, Y: pkey.PublicKey.A.Y},
		},
		Signature: stdeddsa.Signature{
			R: twistededwards.Point{X: sig.R.X, Y: sig.R.Y},
			S: s,
		},
		Message: msgHashFr,
	}
	// assignment.PublicKey.A.X.SetBytes(pkey.PublicKey.A.X.Bytes()[:])
	// Debug witness values
	fmt.Printf("Witness Message: %s\n", msgHashFr.String())
	fmt.Printf("Witness Signature.S: %s\n", s.String())
	fmt.Printf("Witness PublicKey.A.X: %s\n", pkey.PublicKey.A.X.String())
	fmt.Printf("Witness PublicKey.A.Y: %s\n", pkey.PublicKey.A.Y.String())
	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Prove generation time: %x\n", publicWitness)

	// Prove and verify
	startTime := time.Now()
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		panic(fmt.Sprintf("failed to generate proof: %v", err))
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
	err = plonk.Verify(proof, vk, publicWitness)

	if err != nil {
		panic(err)
	}
}
