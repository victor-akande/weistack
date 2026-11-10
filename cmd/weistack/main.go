// Command weistack runs a local emulator of core Huawei Cloud services.
package main

import (
	"fmt"
	"os"

	"github.com/victor-akande/weistack/internal/version"
)

func main() {
	fmt.Fprintln(os.Stdout, version.String())
}
