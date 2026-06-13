package zip

// EncapsulateF4CryptZip is a public wrapper to allow the archiver component
// to call the internal encapsulateF4CryptZip function.
func EncapsulateF4CryptZip(finalPath, tempPath, password string) error {
	return encapsulateF4CryptZip(finalPath, tempPath, password)
}