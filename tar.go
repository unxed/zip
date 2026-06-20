package zip

// EncapsulateXCryptZip is a public wrapper to allow the archiver component
// to call the internal encapsulateXCryptZip function.
func EncapsulateXCryptZip(finalPath, tempPath, password string) error {
	return encapsulateXCryptZip(finalPath, tempPath, password)
}
