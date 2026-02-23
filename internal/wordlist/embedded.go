package wordlist

import _ "embed"

//go:embed dicc.txt
var embeddedWordlist string

//go:embed vhosts.txt
var embeddedVHostWordlist string
