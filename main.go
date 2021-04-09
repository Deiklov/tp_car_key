package main

import (
	"crypto/ed25519"
	"log"
	"math/rand"
	"strconv"
	"time"
)

type object struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}
type Auto struct {
	object
	command              int
	challengeFromCar     []byte
	signedDataFromTinker []byte
}
type Trinket struct {
	object
	challengeFromCar []byte
}

func main() {
	rand.Seed(time.Now().UnixNano())
	pubAuto, privateAuto, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	auto := Auto{
		object: object{
			PrivateKey: privateAuto,
			PublicKey:  pubAuto,
		},
		command: 0,
	}
	pubTrinket, privateTrinket, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	trinket := Trinket{
		object: object{
			PrivateKey: privateTrinket,
			PublicKey:  pubTrinket,
		},
	}
	//0x01 - open
	//0x02 - close
	//0x03 - warm up
	//0x04 - wash
	handshake_data := trinket_generate_handshake(0x03,
		`{ "type": "Вепрь-500","serial_id": 42959024,"year": 2021,"protoc_version": 1.2}`)
	//тачка получила данные
	auto.command = handshake_data
	//данные пришли на тачку, обрабатываем их
	challenge_data := auto.car_process_handshake()
	//брелок получил challenge от тачки
	trinket.challengeFromCar = challenge_data
	//подписываем challenge от тачки
	singedData := trinket.trinket_process_challenge()
	//тачка приняла данные от брелока
	auto.signedDataFromTinker = singedData
	//проверяем подлинность данных
	if auto.verify_signature(trinket.PublicKey) {
		auto.execute_command()
	} else {
		auto.call_the_police()
	}

}
func trinket_generate_handshake(command int, info string) int {
	//info можно использовать как фильтр при приеме сигнала, если не наш тип сигналки, то сразу отбрасываем
	log.Printf("(handshake) trincket -> car, %d(id command)\n", command)
	return command
}
func (car *Auto) car_process_handshake() []byte {
	randInt := rand.Int()
	randIntByte := []byte(strconv.Itoa(rand.Int()))
	log.Printf("(challenge) car -> trinket, %d(challenge for trincket)\n", randInt)
	car.challengeFromCar = randIntByte
	return randIntByte
}

func (trinket *Trinket) trinket_process_challenge() []byte {
	signedData := ed25519.Sign(trinket.PrivateKey, trinket.challengeFromCar)
	return signedData
}

func (car *Auto) verify_signature(pubTrinket ed25519.PublicKey) bool {
	return ed25519.Verify(pubTrinket, car.challengeFromCar, car.signedDataFromTinker)
}
func (car *Auto) execute_command() {
	log.Printf("(action) car: check response - ok, execute command %d", car.command)
}
func (car *Auto) call_the_police() {
	log.Println("(action) car: check response - ERROR, call the police!")
}
