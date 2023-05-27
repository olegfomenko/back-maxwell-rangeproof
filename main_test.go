package back_maxwell_rangeproof

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestBitRepresentation(t *testing.T) {
	fmt.Println(strconv.FormatUint(17, 2))
}

func TestPedersenCommitment(t *testing.T) {
	x, y := Curve.ScalarBaseMult(big.NewInt(123456).Bytes())
	H := ECPoint{x, y}

	proof, commitment, prv, err := CreatePedersenCommitment(H, 10, 5)
	if err != nil {
		panic(err)
	}

	reconstructedCommitment := PedersenCommitment(H, big.NewInt(10), prv)
	fmt.Println("Constructed commitment with prv key: " + reconstructedCommitment.String())
	fmt.Println("Response commitment: " + commitment.String())

	fmt.Println("Private Key: " + hexutil.Encode(prv.Bytes()))

	if err = VerifyPedersenCommitment(H, commitment, proof); err != nil {
		panic(err)
	}
}

func TestPedersenCommitmentFails(t *testing.T) {
	x, y := Curve.ScalarBaseMult(big.NewInt(123456).Bytes())
	H := ECPoint{x, y}

	_, _, _, err := CreatePedersenCommitment(H, 128, 5)
	if err == nil {
		panic("Should fail")
	}
}

func TestSignatureForCommitments(t *testing.T) {
	x, y := Curve.ScalarBaseMult(big.NewInt(123456).Bytes())
	H := ECPoint{x, y}

	proofAlice, commitmentAlice, keyAlice, err := CreatePedersenCommitment(H, 10, 5)
	if err != nil {
		panic(err)
	}

	if err := VerifyPedersenCommitment(H, commitmentAlice, proofAlice); err != nil {
		panic(err)
	}

	signature, err := Sign(keyAlice, big.NewInt(10), Hash([]byte("12345")), H, commitmentAlice)
	if err != nil {
		panic(err)
	}

	if err := Verify(signature, H, commitmentAlice); err != nil {
		panic(err)
	}
}

func TestSchnorrSignature(t *testing.T) {
	prv, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		panic(err)
	}

	px, py := Curve.ScalarBaseMult(prv.Bytes())
	message := Hash([]byte("Hello world"))

	sig, err := SignSchnorr(prv, ECPoint{px, py}, message)
	if err != nil {
		panic(err)
	}

	if err := VerifySchnorr(sig, ECPoint{px, py}, message); err != nil {
		panic(err)
	}
}

func TestSchnorrSignatureAggregation(t *testing.T) {
	prvAlice, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		panic(err)
	}

	x, y := Curve.ScalarBaseMult(prvAlice.Bytes())
	pubAlice := ECPoint{x, y}

	prvBob, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		panic(err)
	}

	x, y = Curve.ScalarBaseMult(prvBob.Bytes())
	pubBob := ECPoint{x, y}

	x, y = Curve.Add(pubAlice.X, pubAlice.Y, pubBob.X, pubBob.Y)
	pubCombined := ECPoint{x, y}

	message := Hash([]byte("Hello world"))

	sigAlice, err := SignSchnorr(prvAlice, pubCombined, message)
	if err != nil {
		panic(err)
	}

	sigBob, err := SignSchnorr(prvBob, pubCombined, message)
	if err != nil {
		panic(err)
	}

	x, y = Curve.Add(sigAlice.R.X, sigAlice.R.Y, sigBob.R.X, sigBob.R.Y)
	sigCom := SchnorrSignature{
		S: add(sigAlice.S, sigBob.S),
		R: ECPoint{x, y},
	}

	if err := VerifySchnorr(sigCom, pubCombined, message); err != nil {
		panic(err)
	}
}
