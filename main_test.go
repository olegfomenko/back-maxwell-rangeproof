package back_maxwell_rangeproof

import (
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
	H := Point{x, y}

	proof, commitment, prv, err := CreatePedersenCommitment(H, 10, 5)
	if err != nil {
		panic(err)
	}

	reconstructedCommitment := PedersenCommitment(H, big.NewInt(10), prv)
	fmt.Println("Constructed commitment with prv key: " + reconstructedCommitment.String())
	fmt.Println("Response commitment: " + commitment.String())

	fmt.Println("Private Key: " + hexutil.Encode(prv.Bytes()))

	err = VerifyPedersenCommitment(H, commitment, proof)
	if err != nil {
		panic(err)
	}
}

func TestPedersenCommitmentFails(t *testing.T) {
	x, y := Curve.ScalarBaseMult(big.NewInt(123456).Bytes())
	H := Point{x, y}

	_, _, _, err := CreatePedersenCommitment(H, 128, 5)
	if err == nil {
		panic("Should fail")
	}
}
