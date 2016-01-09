#################################################################################
# CBC FUNCTIONS v1.0 for Mircryption 1.11+ by B0unTy © 2005
# require TCL 8.4.x
#
# using : Blowfish Module v1.3 from sourceforge tcllib
#         Base64 Module v2.3.1 from sourceforge tcllib
#         mt_rand Module v1.0.0 from Frank Pilhofer
#
# updated nov 4, 2006 - bugfix by Ripclaw for cbc_decrypt
#
#################################################################################

#### REQUIRED PACKAGES FOR CBC FUNCTIONS ####
package require blowfish
package require base64
package require mt_rand

#### CBC ENCRYPTION FUNCTION ####
proc cbc_encrypt {key text} {
	mt::seed [expr int(rand()*1000000)]
	set iv [string range [mt::rand] end-7 end]
	set cbc [::base64::encode -maxlen 0 "$iv[::blowfish::blowfish -mode cbc -dir enc -iv $iv -key $key -- $text]"]
	return $cbc
}

#### CBC DECRYPTION FUNCTION ####
proc cbc_decrypt {key text} {
	set x [::base64::decode [string range $text 0 end]]
 	binary scan [::blowfish::blowfish -mode cbc -dir dec -iv [string range $x 0 7] -key $key -- [string range $x 8 end]] A* plain
	return "$plain"
}
