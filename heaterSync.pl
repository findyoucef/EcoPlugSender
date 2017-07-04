#!/usr/bin/perl
use strict;
use Data::Buffer;
use feature qw(say);
use IO::Socket;
use Data::Dumper;
use JSON;
use LWP::UserAgent;

main();

sub main{
	my $tokenFileName = 'token';
	my $token = importFile($tokenFileName); 
	my $isHeaterOn = getNestStatus($token);
	if($isHeaterOn eq 'NOT_AUTHORIZED'){
		my $token = getAuthTokenFromNest();
		open (my $fileHandle, '>', $tokenFileName) or die "Could not open file '$tokenFileName' $!";
		print $fileHandle $token;
		close $fileHandle;
		main();
	}
	if($isHeaterOn eq 'TRUE'){
		my $ECOBuffer = writeUdpPacket("write","on");
		sendPacket($ECOBuffer->{buf});	
	}elsif($isHeaterOn eq 'FALSE'){
		my $ECOBuffer = writeUdpPacket("write","off");
		sendPacket($ECOBuffer->{buf});	
	}
}


sub importFile{
=comment
Summary: reads a json file and converts the contents into a perl JSON object.
Parameters: JSON file name
Returns: JSON object
=cut
	my $file = $_[0];
	open(FILE,"$file") or do{
		say "Could not open file $file $!";
		exit 0;
	};
	#Reading an entire file into a string.
	my $token = join("", <FILE>);
	close (FILE);
	return $token;
}

sub writeUdpPacket {
	my $command = $_[0];
	my $turnOn = $_[1];
	
	my $buffer = Data::Buffer->new;
	#Byte 0:3 - Command 0x16000500 = Write, 0x17000500 = Read
	if($command eq 'write'){
		$buffer->put_int8(0x16);
	}else{
		$buffer->put_int8(0x15);
	}
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x05);
	$buffer->put_int8(0x00);
	#Byte 4:7 - Command sequence num - looks random
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x27);
	$buffer->put_int8(0x56);
	#Byte 8:9 - Not sure what this field is - 0x0200 = Write, 0x0000 = Read
	if($command eq 'write'){
		$buffer->put_int8(0x02);
	}else{
		$buffer->put_int8(0x00);
	}
	$buffer->put_int8(0x00);
	#Byte 10:14 - ASCII encoded FW Version - Set in readback only?
	$buffer->put_int8(0x31);
	$buffer->put_int8(0x2E);
	$buffer->put_int8(0x36);
	$buffer->put_int8(0x2E);
	$buffer->put_int8(0x33);
	#Byte 15 - Always 0x0
	$buffer->put_int8(0x00);
	#Byte 16:31 - ECO Plugs ID ASCII Encoded - <ECO-xxxxxxxx>
	$buffer->put_int8(0x45);
	$buffer->put_int8(0x43);
	$buffer->put_int8(0x4F);
	$buffer->put_int8(0x2D);
	$buffer->put_int8(0x37);
	$buffer->put_int8(0x38);
	$buffer->put_int8(0x30);
	$buffer->put_int8(0x36);
	$buffer->put_int8(0x45);
	$buffer->put_int8(0x44);
	$buffer->put_int8(0x44);
	$buffer->put_int8(0x36);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 32:47 - 0's - Possibly extension of Plug ID
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 48:79 - ECO Plugs name as set in app
	$buffer->put_int8(0x48);
	$buffer->put_int8(0x65);
	$buffer->put_int8(0x61);
	$buffer->put_int8(0x74);
	$buffer->put_int8(0x65);
	$buffer->put_int8(0x72);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	##Byte 80:95 - ECO Plugs ID without the 'ECO-' prefix - ASCII Encoded
	$buffer->put_int8(0x37);
	$buffer->put_int8(0x38);
	$buffer->put_int8(0x30);
	$buffer->put_int8(0x36);
	$buffer->put_int8(0x45);
	$buffer->put_int8(0x44);
	$buffer->put_int8(0x44);
	$buffer->put_int8(0x36);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 96:111 - 0's
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 112:115 - Something gets returned here during readback - not sure
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 116:119 - The current epoch time in Little Endian
	$buffer->put_int8(0x3E);
	$buffer->put_int8(0x1F);
	$buffer->put_int8(0xB4);
	$buffer->put_int8(0x16);
	#Byte 120:123 - 0's
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	$buffer->put_int8(0x00);
	#Byte 124:127 - Not sure what this field is - this value works, but i've seen others 0xCDB8422A
	$buffer->put_int8(0x5E);
	$buffer->put_int8(0x75);
	$buffer->put_int8(0xAA);
	$buffer->put_int8(0x46);
	#Byte 128:129 - Power state (only for writes)
	if($command eq 'write'){
		if($turnOn eq 'on'){
			$buffer->put_int8(0x01);
			$buffer->put_int8(0x01);
		}else{
			$buffer->put_int8(0x01);
		}
	}
	return $buffer;
}

sub sendPacket{
	my $packet = $_[0];
	my $sock = IO::Socket::INET->new(
			Proto => 'udp',
			PeerPort => 80,
			PeerAddr => '192.168.1.102',
	) or die "Could not create socket: $\n";
	$sock->send($packet) or die "send error: $!\n";
}


sub getAuthTokenFromNest{
	my $tokenURL = 'https://api.home.nest.com/oauth2/access_token';
    my $code = 'K3DSZ22R';
	my $client_id = '4d9cbe3f-b431-4317-a7ae-4d7345776d42';
	my $client_secret = 'PpHjqiuiysXTgY42uxxPIe79T';
	my $grant_type = 'authorization_code';
	
	my $userAgent = LWP::UserAgent->new;
    my $req = HTTP::Request->new(POST => $tokenURL);
    $req->header('content-type' => 'application/x-www-form-urlencoded');
    my $post_data = "code=$code\&client_id=$client_id\&client_secret=$client_secret\&grant_type=$grant_type";
    $req->content($post_data);
    my $response = $userAgent->request($req);
    if ($response->is_success) {
        my $message = $response->decoded_content;
        my $json = decode_json $message;	
        print Dumper $json;
		my $token = $json->{'access_token'};
        return $token;
    }else {
        #print Dumper $response;
        print "HTTP POST error code: ", $response->code, "\n";
        print "HTTP POST error message: ", $response->message, "\n";
        exit 0;
    }
}


sub getNestStatus{
		my $token = $_[0];
		my $userAgent = LWP::UserAgent->new;
        my $baseRequestUrl = 'https://developer-api.nest.com'; 
        
        #say $requestURL and exit;
        my $req = HTTP::Request->new(GET => $baseRequestUrl);
        $req->header('content-type' => 'application/json');
		
        $req->header('Authorization' => "Bearer $token");
        
        my $response = $userAgent->request($req);
        #print Dumper $response;
        if ($response->is_success) {  
            my $message = $response->decoded_content;
            my $json = decode_json $message;
			#print Dumper $json;
			my $isNestHeating = $json->{'devices'}{'thermostats'}{'OGko1_gTkoEl0z0AOFFvyjAult1UahNq'}{'hvac_state'};
	
			if($isNestHeating eq 'heating'){
				return 'TRUE';
			}else{
				return 'FALSE';
			}
		}else {
			#print Dumper $response;
			print "HTTP POST error code: ", $response->code, "\n";
			print "HTTP POST error message: ", $response->message, "\n";
			return "NOT_AUTHORIZED";
        
		}
}
