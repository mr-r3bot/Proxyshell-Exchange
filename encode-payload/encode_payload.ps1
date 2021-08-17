.\ConsoleApplication1.exe -OutVariable cmdOutput
$Bytes =  [System.Text.Encoding]::UTF8.GetBytes($cmdOutput)
$EncodedText = [Convert]::ToBase64String($Bytes)
echo $EncodedText > encodedPayload.txt