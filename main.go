package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"
)

type object struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}
type Auto object

type Trinket object

func main() {
	rand.Seed(time.Now().UnixNano())
	pubAuto, privateAuto, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	auto := Auto{
		PrivateKey: privateAuto,
		PublicKey:  pubAuto,
	}
	pubTrinket, privateTrinket, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	trinket := Trinket{
		PrivateKey: privateTrinket,
		PublicKey:  pubTrinket,
	}
	fmt.Printf("(registration) 0x%s... (pubkey1 written to trinket), 0x%s... (pubkey2 written to car)\n",
		hex.EncodeToString(pubTrinket)[:20], hex.EncodeToString(pubAuto)[:20])
	fmt.Println("(registration) (privatekey1 written to trinket), (privatekey2 written to car)")
	fmt.Printf("(registration) (car know about trinket pubkey1(0x%s...)!)\n", hex.EncodeToString(pubTrinket)[:20])
	//некий список возможных команд
	//0x01 - open
	//0x02 - close
	//0x03 - warm up
	//0x04 - wash
	command := 0x01
	//брелок создал команду и отправил ее тачке, json это просто некая доп инфа, которая может передаваться реально
	handshake_data := trinket_generate_handshake(command,
		`{ "type": "Вепрь-500","serial_id": 42959024,"year": 2021,"protoc_version": 1.2}`)
	//тачка получила данные от брелока, запомнила их и сгенерила для него challenge
	challenge_data := car_process_handshake(handshake_data)
	//брелок получил challenge от тачки, подписал его своим секретным ключом
	response_data := trinket_process_challenge(challenge_data, trinket.PrivateKey)

	//тачка приняла подписанный challenge от брелока и проверила, что брелок подписал его своим секретным ключом
	if verify_signature(trinket.PublicKey, challenge_data, response_data) {
		auto.execute_command(handshake_data)
	} else {
		auto.call_the_police()
	}

}
func trinket_generate_handshake(command int, info string) int {
	//info можно использовать как фильтр при приеме сигнала, если не наш тип сигналки, то сразу отбрасываем
	fmt.Printf("(handshake) trinket -> car, %d(id command)\n", command)
	return command
}
func car_process_handshake(handshakeData int) []byte {
	fmt.Printf("car remember trinket command %d\n", handshakeData)
	randInt := rand.Int()
	randIntByte := []byte(strconv.Itoa(rand.Int()))
	fmt.Printf("(challenge) car -> trinket, %d(challenge for trinket)\n", randInt)
	return randIntByte
}

func trinket_process_challenge(challenge_data []byte, privateTrinket ed25519.PrivateKey) []byte {
	//подписываем sha256(challenge)
	hashFromMessage := sha256.Sum256(challenge_data)
	signedData := ed25519.Sign(privateTrinket, hashFromMessage[:])
	fmt.Printf("(response) trinket->car: 0x%s... (confirm challenge for trinket)\n", hex.EncodeToString(signedData)[:40])
	return signedData
}

func verify_signature(pubTrinket ed25519.PublicKey, challengeFromCar []byte, signedData []byte) bool {
	hashChallengeFromCar := sha256.Sum256(challengeFromCar)
	return ed25519.Verify(pubTrinket, hashChallengeFromCar[:], signedData)
}
func (car *Auto) execute_command(command int) {
	fmt.Printf("(action) car: check response - ok, execute command %d\n", command)
}
func (car *Auto) call_the_police() {
	fmt.Println("(action) car: check response - ERROR, call the police!")
}
