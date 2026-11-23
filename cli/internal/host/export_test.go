package host

// SetRegularAccount replaces the account check for a test and returns the undo.
func SetRegularAccount(f func(string) bool) func() {
	old := regularAccount
	regularAccount = f
	return func() { regularAccount = old }
}
