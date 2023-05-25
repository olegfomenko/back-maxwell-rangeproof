package back_maxwell_rangeproof

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	eth "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var Base = big.NewInt(2)
var Minus1 = big.NewInt(-1)
var Curve = secp256k1.S256()

type Point struct {
	X, Y *big.Int
}

type Proof struct {
	E0 *big.Int
	C  []Point
	S  []*big.Int
	N  int
}

func PedersenCommitment(H Point, a, r *big.Int) Point {
	aHx, aHy := Curve.ScalarMult(H.X, H.Y, a.Bytes())
	rGx, rGY := Curve.ScalarBaseMult(r.Bytes())

	x, y := Curve.Add(aHx, aHy, rGx, rGY)
	return Point{
		X: x,
		Y: y,
	}
}

func VerifyPedersenCommitment(H Point, C Point, proof Proof) error {
	fmt.Println("Verification")
	var R []Point

	for i := 0; i < proof.N; i++ {
		//calculating ei = Hash(si*G - e0(Ci - 2^i*H))
		x, y := Curve.ScalarBaseMult(proof.S[i].Bytes())
		siG := Point{x, y}

		x, y = Curve.ScalarMult(H.X, H.Y, minus(pow2(i)).Bytes())
		x, y = Curve.Add(proof.C[i].X, proof.C[i].Y, x, y)
		x, y = Curve.ScalarMult(x, y, minus(proof.E0).Bytes())
		x, y = Curve.Add(x, y, siG.X, siG.Y)
		ei := HashPoints(Point{x, y})

		fmt.Println("ei #" + fmt.Sprint(i) + " " + ei.String())

		x, y = Curve.ScalarMult(proof.C[i].X, proof.C[i].Y, ei.Bytes())
		R = append(R, Point{x, y})
	}

	//fmt.Println("R: ")
	//for _, r := range R {
	//	fmt.Println(r.X.String() + " " + r.Y.String())
	//}

	// eo_ = Hash(Ro||R1||...Rn-1)
	e0_ := HashPoints(R...)

	// C = sum(Ci)
	x, y := proof.C[0].X, proof.C[0].Y
	for i := 1; i < proof.N; i++ {
		x, y = Curve.Add(x, y, proof.C[i].X, proof.C[i].Y)
	}

	//fmt.Println("e0: " + proof.E0.String())
	//fmt.Println("e0_: " + e0_.String())

	if e0_.Cmp(proof.E0) != 0 {
		return errors.New("e0 != e0_")
	}

	if C.X.Cmp(x) != 0 || C.Y.Cmp(y) != 0 {
		return errors.New("C != sum(Ci)")
	}

	return nil
}

func CreatePedersenCommitment(H Point, val uint64, n int) (Proof, Point, *big.Int, error) {
	// Converting into bit representation
	bitsStr := strconv.FormatUint(val, 2)
	var bits []bool
	for i := len(bitsStr) - 1; i >= 0; i-- {
		bits = append(bits, bitsStr[i] == '1')
	}

	if len(bits) > n {
		return Proof{}, Point{}, nil, errors.New("invalid value: greater then 2^n - 1")
	}

	// Adding leading zeros
	for len(bits) < n {
		bits = append(bits, false)
	}

	fmt.Println(bits)

	prv := big.NewInt(0)
	var r []*big.Int
	var k []*big.Int

	var R []Point
	var C []Point

	for i := 0; i < n; i++ {
		if bits[i] {
			ri, err := rand.Int(rand.Reader, Curve.Params().N)
			if err != nil {
				return Proof{}, Point{}, nil, err
			}
			prv = add(prv, ri)
			r = append(r, ri)

			// Ci = Com(2^i, ri)
			Ci := PedersenCommitment(H, pow2(i), ri)
			C = append(C, Ci)

			ki, err := rand.Int(rand.Reader, Curve.Params().N)
			if err != nil {
				return Proof{}, Point{}, nil, err
			}
			k = append(k, ki)

			// Hash(ki*G)
			x, y := Curve.ScalarBaseMult(ki.Bytes())
			ei := HashPoints(Point{x, y})

			fmt.Println("Hash(ki*G) #" + fmt.Sprint(i) + " " + ei.String())

			// Ri = Hash(ki*G)*Ci
			x, y = Curve.ScalarMult(Ci.X, Ci.Y, ei.Bytes())
			R = append(R, Point{
				X: x,
				Y: y,
			})
			continue
		}

		ki0, err := rand.Int(rand.Reader, Curve.Params().N)
		if err != nil {
			return Proof{}, Point{}, nil, err
		}
		k = append(k, ki0)

		// Ri = ki0*G
		x, y := Curve.ScalarBaseMult(ki0.Bytes())
		R = append(R, Point{
			X: x,
			Y: y,
		})

		// will be initialized later
		C = append(C, Point{})
		// just placing nil value to be able to get corresponding r[i] for bit == 1 in future
		r = append(r, nil)
	}

	//fmt.Println("R: ")
	//for _, r := range R {
	//	fmt.Println(r.X.String() + " " + r.Y.String())
	//}

	// eo = Hash(Ro||R1||...Rn-1)
	e0 := HashPoints(R...)

	var s []*big.Int

	for i := 0; i < n; i++ {
		if bits[i] {
			// si = ki + e0*r^i
			si := add(k[i], mul(e0, r[i]))
			s = append(s, si)
			continue
		}

		ki, err := rand.Int(rand.Reader, Curve.Params().N)
		if err != nil {
			return Proof{}, Point{}, nil, err
		}

		// ei = Hash(ki*G + e0*2^i*H)
		ei := HashPoints(PedersenCommitment(H, mul(e0, pow2(i)), ki))

		fmt.Println("ei #" + fmt.Sprint(i) + " " + ei.String())

		// Ci = Ri /ei = (ki0/ei)*G
		ei_inverse := new(big.Int).ModInverse(ei, Curve.Params().N)
		x, y := Curve.ScalarMult(R[i].X, R[i].Y, ei_inverse.Bytes())
		C[i] = Point{x, y}

		prv = add(prv, mul(k[i], ei_inverse))

		// si = ki + (ki0 * e0)/ei
		si := add(ki, mul(mul(k[i], e0), ei_inverse))
		s = append(s, si)
	}

	x, y := C[0].X, C[0].Y
	for i := 1; i < n; i++ {
		x, y = Curve.Add(x, y, C[i].X, C[i].Y)
	}

	return Proof{
			E0: e0,
			C:  C,
			S:  s,
			N:  n,
		},
		Point{x, y},
		prv,
		nil
}

func add(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(x, y), Curve.Params().N)
}

func mul(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(x, y), Curve.Params().N)
}

func pow2(i int) *big.Int {
	return new(big.Int).Exp(Base, big.NewInt(int64(i)), Curve.Params().N)
}

func minus(val *big.Int) *big.Int {
	return new(big.Int).Mul(val, big.NewInt(-1))
}

func Hash(bytes ...[]byte) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetBytes(eth.Keccak256(bytes...)), Curve.Params().N)
}

func HashPoints(points ...Point) *big.Int {
	var data [][]byte
	for _, p := range points {
		data = append(data, p.X.Bytes())
		data = append(data, p.Y.Bytes())
	}

	return Hash(data...)
}
