package ckks

import "github.com/ldsec/lattigo/v2/utils"
import "github.com/ldsec/lattigo/v2/ring"

func GetCiphertextPartAsElement(ciphertext *Ciphertext, idx int) *Element {
	if idx < len(ciphertext.value) {
		return &Element{
			value: ciphertext.value[idx:idx+1],
			scale: ciphertext.scale,
			isNTT: ciphertext.isNTT,
		}
	} else{
		return nil
	}
}

func GetSeckeyAsElement(key *SecretKey) *Element {
	return &Element{
		value: []*ring.Poly{key.Get()},
		scale: 0,
		isNTT: true,
	}
}

func IsSame(el0, el1 *Element) bool {
	lvl := utils.MinUint64(el0.Level(), el1.Level())
	n := utils.MinUint64(uint64(len(el0.value[0].Coeffs[0])), uint64(len(el1.value[0].Coeffs[0])))
	for row := uint64(0); row <= lvl; row++ {
		row0, row1 := el0.value[0].Coeffs[row], el1.value[0].Coeffs[row]
		for i := uint64(0); i < n; i++ {
			if row0[i] != row1[i] {
				return false
			}
		}
	}
	return true;
}