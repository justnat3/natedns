package main

func Copy(src []int, dst []int, size int) {

	for i := 0; i < size; i++ {
		dst[i] = src[i]
	}

}

func main() {
	// make == malloc()
	// clear == free()
	newfoo := make([]int, 4)

	foo := make([]int, 4)
	for i := range 4 {
		foo[i] = i + 1 // [1,2,3,4]
	}

	// sizeof(foo) = 4
	Copy(foo, newfoo, 4)

	for i := range newfoo {
		println(newfoo[i])
	}

	clear(foo)
	clear(newfoo)
}
