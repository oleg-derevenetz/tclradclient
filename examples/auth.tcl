#!/usr/local/bin/tclsh

lappend auto_path "../.."

package require udp
package require radclient

set RADIUS_HOST			"192.168.1.1"
set RADIUS_PORT			1812
set RADIUS_TIMEOUT		5000
set RADIUS_SECRET		"secret"
set RADIUS_USERNAME		"user"
set RADIUS_PASSWORD		"pass"
set RADIUS_NAS_IP_ADDRESS	"192.168.2.1"
set RADIUS_NAS_PORT		"1"
set RADIUS_NAS_PORT_TYPE	"Virtual"

set AfterTimeout		""
set QueryResult			""

proc radius_timeout {} {
    global QueryResult

    set QueryResult "Timeout"
}

proc radius_reply {sock radius_secret radius_host_ip radius_port request_id} {
    global AfterTimeout QueryResult

    set body [read       $sock]
    set peer [fconfigure $sock -peer]

    set peer_addr [lindex $peer 0]
    set peer_port [lindex $peer 1]

    if {$peer_port==$radius_port && [string equal $radius_host_ip $peer_addr]} {
	if {![catch {array set reply [::radclient::packet_parse $body $radius_secret]} Err]} {
	    if {![catch {set reply_id $reply(X-Id)}] && [regexp {^\d+$} $reply_id]} {
		if {$reply_id==$request_id} {
		    after cancel $AfterTimeout

		    if {[catch {set code $reply(X-Code)}]} {
			set QueryResult "Error decoding RADIUS auth reply packet type: Packet-Type field not found"
		    } elseif {[catch {set pkt_type [::radclient::dict_get_val_by_id "Packet-Type" $code]} Err]} {
			set QueryResult "Error decoding RADIUS auth reply packet type: $Err"
		    } else {
			set QueryResult $pkt_type
		    }
		} else {
		    puts "Ignoring RADIUS auth reply with unknown id $reply_id from $peer_addr:$peer_port"
		}
	    } else {
		puts "Ignoring RADIUS auth reply with invalid id from $peer_addr:$peer_port"
	    }
	} else {
	    puts "Error parsing RADIUS auth reply from $peer_addr:$peer_port: $Err"
	}
    } else {
	puts "Ignoring bogus packet from $peer_addr:$peer_port"
    }
}

::radclient::dict_set_path "../dict"
::radclient::dict_parse    "dictionary"

if {[catch {set sock [udp_open]} Err]} {
    puts "Error creating socket: $Err"
} else {
    array unset request
    array set   request {}

    set request(X-Id)           [expr int( rand() * 100 )]
    set request(X-Vector)       [::radclient::make_auth_vector]
    set request(X-Code)         [::radclient::dict_get_val_by_name "Packet-Type" "Access-Request"]
    set request(User-Name)      [list $RADIUS_USERNAME]
    set request(Password)       [list $RADIUS_PASSWORD]
    set request(NAS-IP-Address) [list $RADIUS_NAS_IP_ADDRESS]
    set request(NAS-Port)       [list $RADIUS_NAS_PORT]
    set request(NAS-Port-Type)  [list $RADIUS_NAS_PORT_TYPE]

    fconfigure $sock -blocking 0 -buffering none -translation binary -remote [list $RADIUS_HOST $RADIUS_PORT]
    fileevent  $sock readable [list radius_reply $sock $RADIUS_SECRET $RADIUS_HOST $RADIUS_PORT $request(X-Id)]

    if {[catch {
	puts -nonewline $sock [::radclient::make_packet [array get request] $RADIUS_SECRET 0]
    } Err]} {
	puts "Error sending RADIUS auth request: $Err"

	catch {close $sock}
    } else {
	set AfterTimeout [after $RADIUS_TIMEOUT radius_timeout]

	vwait QueryResult

	if {[catch {close $sock} Err]} {
	    puts "Error closing socket: $Err"
	} else {
	    puts $QueryResult
	}
    }
}
