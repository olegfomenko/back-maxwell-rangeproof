package back_maxwell_rangeproof

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"
)

func TestBitRepresentation(t *testing.T) {
	fmt.Println(strconv.FormatUint(17, 2))
}

func TestPedersenCommitment(t *testing.T) {
	x, y := Curve.ScalarBaseMult(big.NewInt(123456).Bytes())
	H := Point{x, y}

	proof, C, _, err := CreatePedersenCommitment(H, 10, 5)
	if err != nil {
		panic(err)
	}

	//fmt.Println(PedersenCommitment(H, big.NewInt(10), r))
	//fmt.Println(C)

	//fmt.Println(r.String())

	err = VerifyPedersenCommitment(H, C, proof)
	if err != nil {
		panic(err)
	}
}
