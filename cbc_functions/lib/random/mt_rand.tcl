#
# ----------------------------------------------------------------------
# Mersenne Twister Random Number Generator
#
# Derived from the source code for MT19937 by Takuji Nishimura
# and Makoto Matsumoto, which is available from their homepage
# at http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
#
# Written by Frank Pilhofer. Released under BSD license.
# ----------------------------------------------------------------------
#
package require Tcl 8.4

namespace eval mt {
   variable version 1.0.0
   variable rcsid {$Id: mt_rand.tcl,v 1.0 Frank Pilhofer Exp $}
   variable N 624
   variable M 397
   variable MATRIX_A 0x9908b0df
   variable UPPER_MASK 0x80000000
   variable LOWER_MASK 0x7fffffff
   variable mag010 0
   variable mag011 $MATRIX_A
   variable mt
   variable mti
}

#
# Initializes with a seed
#

proc mt::seed {s} {
   variable N
   variable mt
   variable mti

   set mt [list [expr {$s & 0xffffffff}]]
   set mtimm $mt

   for {set mti 1} {$mti < $N} {incr mti} {
set t1 [expr {$mtimm ^ ($mtimm >> 30)}]
set t2 [expr {1812433253 * $t1 + $mti}]
set mtimm [expr {$t2 & 0xffffffff}]
lappend mt $mtimm
   }
}

#
# Initialize from a (binary) seed string
#

proc mt::init {s} {
   variable N
   variable mt

   seed 19650218

   set i 1
   set j 0

   #
   # The algorithm wants a list of 32 bit integers for the key
   #

   set slen [string length $s]

   if {($slen % 4) != 0} {
append s [string repeat "\0" [expr {4-($slen%4)}]]
   }

   binary scan $s i* key

   if {$N > [llength $key]} {
set k $N
   } else {
set k [llength $key]
   }

   set mtimm [lindex $mt 0]

   for {} {$k} {incr k -1} {
set keyj [lindex $key $j]
set mti [lindex $mt $i]
set t1 [expr {$mtimm ^ ($mtimm >> 30)}]
set t2 [expr {$mti ^ ($t1 * 1664525)}]
set t3 [expr {$t2 + $keyj + $j}]
set mtimm [expr {$t3 & 0xffffffff}]
set mt [lreplace $mt $i $i $mtimm]
incr i
incr j
if {$i >= $N} {
    set mt [lreplace $mt 0 0 $mtimm]
    set i 1
}
if {$j >= [llength $key]} {
    set j 0
}
   }

   for {set k [expr {$N-1}]} {$k} {incr k -1} {
set mti [lindex $mt $i]
set t1 [expr {$mtimm ^ ($mtimm >> 30)}]
set t2 [expr {$mti ^ ($t1 * 1566083941)}]
set t3 [expr {$t2 - $i}]
set mtimm [expr {$t3 & 0xffffffff}]
set mt [lreplace $mt $i $i $mtimm]
incr i
if {$i >= $N} {
    set mt [lreplace $mt 0 0 $mtimm]
    set i 1
}
   }

   set mt [lreplace $mt 0 0 0x80000000]
}

#
# Produce some more random numbers
#

proc mt::more {} {
   variable N
   variable M
   variable mt
   variable mti
   variable MATRIX_A
   variable UPPER_MASK
   variable LOWER_MASK
   variable mag010
   variable mag011

   if {$mti == [expr {$N+1}]} {
seed 5489
   }

   set newmt [list]

   for {set kk 0} {$kk<[expr {$N-$M}]} {incr kk} {
set mtkk [lindex $mt $kk]
set mtkkpp [lindex $mt [expr {$kk+1}]]
set mtkkpm [lindex $mt [expr {$kk+$M}]]
set y [expr {($mtkk & $UPPER_MASK) | ($mtkkpp & $LOWER_MASK)}]
if {($y & 1) == 0} {
    set mag01 $mag010
} else {
    set mag01 $mag011
}
set mtkk [expr {$mtkkpm ^ ($y >> 1) ^ $mag01}]
lappend newmt $mtkk
   }
   for {} {$kk<[expr {$N-1}]} {incr kk} {
set mtkk [lindex $mt $kk]
set mtkkpp [lindex $mt [expr {$kk+1}]]
set mtkkpm [lindex $newmt [expr {$kk+$M-$N}]]
set y [expr {($mtkk & $UPPER_MASK) | ($mtkkpp & $LOWER_MASK)}]
if {($y & 1) == 0} {
    set mag01 $mag010
} else {
    set mag01 $mag011
}
set mtkk [expr {$mtkkpm ^ ($y >> 1) ^ $mag01}]
lappend newmt $mtkk
   }
   set mtnm1 [lindex $mt [expr {$N-1}]]
   set mt0 [lindex $newmt 0]
   set mtmmm [lindex $newmt [expr {$M-1}]]
   set y [expr {($mtnm1 & $UPPER_MASK) | ($mt0 & $LOWER_MASK)}]
   if {($y & 1) == 0} {
set mag01 $mag010
   } else {
set mag01 $mag011
   }
   set mtkk [expr {$mtmmm ^ ($y >> 1) ^ $mag01}]
   lappend newmt $mtkk

   set mti 0
   set mt $newmt
}

#
# ----------------------------------------------------------------------
# Public interface
# ----------------------------------------------------------------------
#

#
# Initialize with a random (binary string) seed
#

proc mt::srand {seed} {
   init $seed
}

#
# Generates an integer random number in the [0,0xffffffff] interval
#

proc mt::int32 {} {
   variable N
   variable mt
   variable mti

   if {$mti >= $N} {
more
   }

   set y [lindex $mt $mti]
   incr mti

   set y [expr {$y ^  ($y >> 11)}]
   set y [expr {$y ^ (($y <<  7) & 0x9d2c5680)}]
   set y [expr {$y ^ (($y << 15) & 0xefc60000)}]
   set y [expr {$y ^  ($y >> 18)}]

   return [expr {$y & 0xffffffff}]
}

#
# Generates a floating-point random number in the [0,1) interval
#

proc mt::rand {} {
   set i [int32]
   return [expr {double($i) / 4294967296.0}]
}

#
# ----------------------------------------------------------------------
# Print test vectors, for comparison with the original code
# ----------------------------------------------------------------------
#

proc mt::test {} {
   srand [binary format i4 [list 0x123 0x234 0x345 0x456]]
   puts "1000 outputs of int32"
   for {set i 0} {$i < 1000} {incr i} {
puts -nonewline [format "%10u " [int32]]
if {($i % 5) == 4} {
    puts ""
}
   }
   puts "1000 outputs of real"
   for {set i 0} {$i < 1000} {incr i} {
puts -nonewline [format "%10.8f " [rand]]
if {($i % 5) == 4} {
    puts ""
}
   }
}

package provide mt_rand $mt::version
