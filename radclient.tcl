package require md5

namespace eval ::radclient {
    namespace export dict_set_path dict_parse dict_get_attr_by_id dict_get_attr_by_name dict_get_val_by_id dict_get_val_by_name
    namespace export make_auth_vector make_acct_vector packet_parse make_packet

    variable  DICT_PATH      "."

    array set DICT_ATTR_ID   {}
    variable  DICT_ATTR_ID

    array set DICT_ATTR_NAME {}
    variable  DICT_ATTR_NAME

    array set DICT_VAL_ID    {}
    variable  DICT_VAL_ID

    array set DICT_VAL_NAME  {}
    variable  DICT_VAL_NAME

    proc dict_set_path {dict_path} {
        variable DICT_PATH

        set DICT_PATH $dict_path
    }

    proc dict_parse {dict_name} {
        variable DICT_PATH

        set vendor 0

        set fd [open "$DICT_PATH/$dict_name"]
        while {[gets $fd line]>=0} {
            if {![regexp {^#} $line] && ![regexp {^\s*$} $line]} {
                if {[catch {
                    set vendor [dict_parse_line $line $vendor]
                } Err]} {
                    close $fd
                    error "Error parsing dictionary file $dict_name: $Err"
                }
            }
        }
        close $fd
    }

    proc dict_parse_line {line vendor} {
        variable DICT_ATTR_ID
        variable DICT_ATTR_NAME
        variable DICT_VAL_ID
        variable DICT_VAL_NAME

        if {[regexp {^\s*\$INCLUDE\s+([^\s]+)} $line dummy incl_file]} {
            dict_parse $incl_file
        } elseif {[regexp {^\s*VENDOR\s+[^\s]+\s+([xXoO[:xdigit:]]+)} $line dummy vnd]} {
            if {![catch {expr $vnd}]} {
                set vendor [expr $vnd]
            }
        } elseif {[regexp {^\s*ATTRIBUTE\s+([^\s]+)\s+([xXoO[:xdigit:]]+)\s+([^\s]+)} $line dummy attr_name attr_id attr_type]} {
            if {![catch {expr $attr_id}]} {
                set DICT_ATTR_ID([list $vendor [expr $attr_id]]) [list $attr_name $attr_type]
                set DICT_ATTR_NAME($attr_name)                   [list $vendor [expr $attr_id] $attr_type]
            }
        } elseif {[regexp {^\s*VALUE\s+([^\s]+)\s+([^\s]+)\s+([xXoO[:xdigit:]]+)} $line dummy val_attr val_name val_id]} {
            if {![catch {expr $val_id}]} {
                set DICT_VAL_ID([list $val_attr $val_id])     $val_name
                set DICT_VAL_NAME([list $val_attr $val_name]) [expr $val_id]
            }
        }
        return $vendor
    }

    proc dict_get_attr_by_id {vendor attr_id} {
        variable DICT_ATTR_ID

        if {![catch {set value $DICT_ATTR_ID([list $vendor $attr_id])}]} {
            return $value
        } else {
            error "Could not find attribute with vendor $vendor and id $attr_id"
        }
    }

    proc dict_get_attr_by_name {attr_name} {
        variable DICT_ATTR_NAME

        if {![catch {set value $DICT_ATTR_NAME($attr_name)}]} {
            return $value
        } else {
            error "Could not find attribute with name $attr_name"
        }
    }

    proc dict_get_val_by_id {val_attr val_id} {
        variable DICT_VAL_ID

        if {![catch {set value $DICT_VAL_ID([list $val_attr $val_id])}]} {
            return $value
        } else {
            error "Could not find value with attribute $val_attr and id $val_id"
        }
    }

    proc dict_get_val_by_name {val_attr val_name} {
        variable DICT_VAL_NAME

        if {![catch {set value $DICT_VAL_NAME([list $val_attr $val_name])}]} {
            return $value
        } else {
            error "Could not find value with attribute $val_attr and name $val_name"
        }
    }

    proc make_auth_vector {} {
        set vector ""

        for {set i 0} {$i<32} {incr i} {
            append vector [expr int( rand() * 10 )]
        }

        return $vector
    }

    proc make_acct_vector {} {
        set vector ""

        for {set i 0} {$i<32} {incr i} {
            append vector 0
        }

        return $vector
    }

    proc pwd_encode {value secret vector} {
        if {[catch {
            set bcnt [expr (([string length $value] - 1) / 16) + 1]
            set pwd  ""

            set md5 [::md5::MD5Init]

            ::md5::MD5Update $md5 $secret
            ::md5::MD5Update $md5 [binary format "H*" $vector]

            binary scan [::md5::MD5Final $md5] "iiii" bi1 bi2 bi3 bi4

            for {set i 0} {$i<$bcnt} {incr i} {
                set p [string range $value [expr $i * 16] [expr $i * 16 + 15]]

                while {[string length $p]<16} {
                    append p "\000"
                }

                binary scan $p "iiii" p1 p2 p3 p4

                set px1 [expr $p1 ^ $bi1]
                set px2 [expr $p2 ^ $bi2]
                set px3 [expr $p3 ^ $bi3]
                set px4 [expr $p4 ^ $bi4]

                append pwd [binary format "iiii" $px1 $px2 $px3 $px4]

                set md5 [::md5::MD5Init]

                ::md5::MD5Update $md5 $secret
                ::md5::MD5Update $md5 [binary format "iiii" $px1 $px2 $px3 $px4]

                binary scan [::md5::MD5Final $md5] "iiii" bi1 bi2 bi3 bi4
            }
        } Err]} {
            error "Error encoding password: $Err"
        } else {
            return $pwd
        }
    }

    proc pwd_decode {value secret vector} {
        if {[catch {
            set bcnt [expr (([string length $value] - 1) / 16) + 1]
            set pwd  ""

            set md5 [::md5::MD5Init]

            ::md5::MD5Update $md5 $secret
            ::md5::MD5Update $md5 [binary format "H*" $vector]

            binary scan [::md5::MD5Final $md5] "iiii" bi1 bi2 bi3 bi4

            for {set i 0} {$i < $bcnt} {incr i} {
                set p1 $bi1
                set p2 $bi2
                set p3 $bi3
                set p4 $bi4

                binary scan [string range $value [expr $i * 16] [expr $i * 16 + 15]] "iiii" p1 p2 p3 p4

                set px1 [expr $p1 ^ $bi1]
                set px2 [expr $p2 ^ $bi2]
                set px3 [expr $p3 ^ $bi3]
                set px4 [expr $p4 ^ $bi4]

                append pwd [binary format "iiii" $px1 $px2 $px3 $px4]

                set md5 [::md5::MD5Init]

                ::md5::MD5Update $md5 $secret
                ::md5::MD5Update $md5 [string range $value [expr $i * 16] [expr $i * 16 + 15]]

                binary scan [::md5::MD5Final $md5] "iiii" bi1 bi2 bi3 bi4
            }
        } Err]} {
            error "Error decoding password: $Err"
        } else {
            return [string trim $pwd "\000"]
        }
    }

    proc format_value {type name value secret vector} {
        switch -exact -- $type {
            string {
                if {[string equal $name "CHAP-Password"]} {
                    binary scan $value "H*" chap

                    return $chap
                } elseif {[string equal $name "Password"]} {
                    set pwd [pwd_decode $value $secret $vector]

                    return $pwd
                } else {
                    return [string trim $value "\000"]
                }
            }
            integer {
                if {[binary scan $value "I" val]==1} {
                    set val [expr ( $val + 0x100000000 ) % 0x100000000]

                    if {![catch {set val_name [dict_get_val_by_id $val $name]}]} {
                        return $val_name
                    } else {
                        return $val
                    }
                } else {
                    error "Error decoding value with type $type, name $name and value $value"
                }
            }
            ipaddr {
                if {[binary scan $value "cccc" p1 p2 p3 p4]==4} {
                    set p1 [expr $p1 & 0xFF]
                    set p2 [expr $p2 & 0xFF]
                    set p3 [expr $p3 & 0xFF]
                    set p4 [expr $p4 & 0xFF]

                    return "$p1.$p2.$p3.$p4"
                } else {
                    error "Error decoding value with type $type, name $name and value $value"
                }
            }
            date {
                if {[binary scan $value "I" val]==1} {
                    return $val
                } else {
                    error "Error decoding value with type $type, name $name and value $value"
                }
            }
            octets {
                return $value
            }
            default {
                error "Error decoding value with type $type, name $name and value $value"
            }
        }
    }

    proc packet_parse_at_pos {body pos secret vector} {
        set vendor 0

        if {[binary scan [string range $body $pos [incr pos]] "c" av_type]==1 &&
            [binary scan [string range $body $pos [incr pos]] "c" av_len]==1} {
            set av_type [expr $av_type & 0xFF]
            set av_len  [expr $av_len  & 0xFF]

            set ret_len $av_len

            if {$av_type==[lindex [dict_get_attr_by_name "Vendor-Specific"] 1]} {
                if {[binary scan [string range $body $pos [incr pos 4]] "I" vendor]==1  &&
                    [binary scan [string range $body $pos [incr pos 1]] "c" av_type]==1 &&
                    [binary scan [string range $body $pos [incr pos 1]] "c" av_len]==1} {
                    set av_type [expr $av_type & 0xFF]
                    set av_len  [expr $av_len  & 0xFF]
                } else {
                    error "Parse error at position $pos"
                }
            }
            if {$ret_len<=2} {
                return [list $ret_len]
            } else {
                set value [string range $body $pos [expr $pos + $av_len - 3]]
                if {![catch {set attr [dict_get_attr_by_id $vendor $av_type]}]} {
                    set name  [lindex $attr 0]
                    set value [format_value [lindex $attr 1] $name $value $secret $vector]
                } else {
                    set name  $av_type
                }
                return [list $ret_len $vendor $av_type $name $value]
            }
        } else {
            error "Parse error at position $pos"
        }
    }

    proc packet_parse {body secret} {
        if {[binary scan $body "ccSH32" code id len vector]==4} {
            set code [expr $code & 0xFF]
            set id   [expr $id   & 0xFF]
            set len  [expr $len  & 0xFFFF]

            array set avp {}

            set avp(X-Id)     $id
            set avp(X-Code)   $code
            set avp(X-Vector) $vector

            set pos 20

            while {$pos<$len} {
                if {[catch {set res [packet_parse_at_pos $body $pos $secret $vector]} Err]} {
                    error "Error when parsing packet: $Err"
                } else {
                    incr pos [lindex $res 0]
                    if {[llength $res]==5} {
                        if {[string equal [lindex $res 2] "string"]} {
                            set val [string trim [lindex $res 4]]
                        } else {
                            set val [lindex $res 4]
                        }
                        lappend avp([lindex $res 3]) $val
                    }
                }
            }

            return [array get avp]
        } else {
            error "Error when parsing packet: Invalid packet format"
        }
    }

    proc encode_pair {name value secret vector} {
        if {[catch {set attr [dict_get_attr_by_name $name]}]} {
            error "Unknown attribute: $name"
        } else {
            set vendor [lindex $attr 0]
            set id     [lindex $attr 1]
            set type   [lindex $attr 2]

            catch {
                set value [dict_get_val_by_name $name $value]
            }

            switch -exact -- $type {
                string {
                    if {[string equal $name "CHAP-Password"]} {
                        set payload [binary format "H*" $value]
                    } elseif {[string equal $name "Password"]} {
                        set payload [pwd_encode $value $secret $vector]
                    } else {
                        set payload $value
                    }
                    set len [string length $payload]
                }
                integer {
                    set payload [binary format "I" $value]
                    set len     4
                }
                ipaddr {
                    if {[regexp {(\d+)\.(\d+)\.(\d+)\.(\d+)} $value dummy p1 p2 p3 p4]} {
                        set payload [binary format "cccc" $p1 $p2 $p3 $p4]
                        set len     4
                    } else {
                        error "Invalid IP address: $value"
                    }
                }
                date {
                    set payload [binary format "I" $ival]
                    set len     4
                }
                octets {
                    set payload $value
                    set len     [string length $payload]
                }
                default {
                    error "Invalid attribute type: $type"
                }
            }
            incr len 2

            if {$vendor==0} {
                set  pair [binary format "cc" $id $len]
            } else {
                set  pair [binary format "ccIcc" [lindex [dict_get_attr_by_name "Vendor-Specific"] 1] [expr $len + 6] $vendor $id $len]
                incr len  6
            }
            append pair $payload

            return [list $len $pair]
        }
    }

    proc make_packet {pkt secret make_auth} {
        array set avp $pkt

        if {[catch {set id     $avp(X-Id);     unset avp(X-Id)}]   ||
            [catch {set code   $avp(X-Code);   unset avp(X-Code)}] ||
            [catch {set vector $avp(X-Vector); unset avp(X-Vector)}]} {
            error "Required attribute not present"
        } else {
            set avps_len  0
            set avps_pack ""

            foreach name [array names avp] {
                foreach value $avp($name) {
                    if {[catch {set pair_data [encode_pair $name $value $secret $vector]} Err]} {
                        error "Error encoding pair with name $name and value $value: $Err"
                    } else {
                        incr   avps_len  [lindex $pair_data 0]
                        append avps_pack [lindex $pair_data 1]
                    }
                }
            }
            incr avps_len 20

            set packet [binary format "ccS" $code $id $avps_len]

            if {$make_auth} {
                set bin_vector [binary format "H*" $vector]
                set md5        [::md5::MD5Init]

                set    hash $packet
                append hash $bin_vector
                append hash $avps_pack
                append hash $secret

                ::md5::MD5Update $md5 $hash

                set vector [::md5::MD5Final $md5]
            } else {
                set vector [binary format H* $vector]
            }

            append packet $vector
            append packet $avps_pack

            return $packet
        }
    }
}

package provide radclient 1.0.0
