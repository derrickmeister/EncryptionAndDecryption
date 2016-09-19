Imports System.IO
Imports System.Security.Cryptography
Imports System.Windows.Forms

Class MainWindow

    Dim cspp As New CspParameters
    Dim rsa As RSACryptoServiceProvider

    Dim BaseFolder As String
    Dim EncrFolder As String = "c:\Encrypt\"
    Dim DecrFolder As String = "c:\Decrypt\"
    Dim SrcFolder As String = "c:\Docs\"

    Dim PubkeyFile As String = "c:\Encrypt\rsaPublicKey.txt"

    Dim keyName As String = "Key01"

    Private Sub MainWindow_Loaded(sender As Object, e As RoutedEventArgs) Handles Me.Loaded
        InitWorkingFolder()
    End Sub

    Private Sub InitWorkingFolder()
        Dim folderBrowser As New FolderBrowserDialog
        folderBrowser.Description = "Select work folder for encryption and decryption test"
        folderBrowser.RootFolder = Environment.SpecialFolder.Desktop
        If folderBrowser.ShowDialog = Forms.DialogResult.OK Then
            BaseFolder = folderBrowser.SelectedPath
        End If
    End Sub

    Private Sub btnCreateAsmKeys_Click(sender As Object, e As RoutedEventArgs) Handles btnCreateAsmKeys.Click
        cspp.KeyContainerName = keyName
        rsa = New RSACryptoServiceProvider(cspp)
        rsa.PersistKeyInCsp = True

        If rsa.PublicOnly Then
            label1.Content = "Key: " + cspp.KeyContainerName + " - Public Only"
        Else
            label1.Content = "Key: " + cspp.KeyContainerName + " - Full Key Pair"
        End If
    End Sub

    Private Sub btnEncryptFile_Click(sender As Object, e As RoutedEventArgs) Handles btnEncryptFile.Click
        If rsa Is Nothing Then
            MsgBox("Key not set.")
        Else
            Dim openFileDialog As New OpenFileDialog
            openFileDialog.InitialDirectory = SrcFolder
            If openFileDialog.ShowDialog Then
                Try
                    Dim fName As String = openFileDialog.FileName
                    If Not String.IsNullOrEmpty(fName) Then
                        Dim fInfo As New IO.FileInfo(fName)
                        EncryptFile(fInfo)
                    End If
                Catch ex As Exception
                    MsgBox(ex.Message)
                End Try
            End If
        End If
    End Sub

    Private Sub EncryptFile(inFile As FileInfo)
        Dim rjndl As New RijndaelManaged
        rjndl.KeySize = 256
        rjndl.BlockSize = 256
        rjndl.Mode = CipherMode.CBC
        Dim transform As ICryptoTransform = rjndl.CreateEncryptor

        Dim keyEncrypted() As Byte = rsa.Encrypt(rjndl.Key, False)

        Dim LenK() As Byte = New Byte((4) - 1) {}
        Dim LenIV() As Byte = New Byte((4) - 1) {}
        Dim lKey As Integer = keyEncrypted.Length
        LenK = BitConverter.GetBytes(lKey)
        Dim lIV As Integer = rjndl.IV.Length
        LenIV = BitConverter.GetBytes(lIV)

        Dim outFile As String = (EncrFolder + (inFile.Name.Substring(0, inFile.Name.LastIndexOf(".")) + ".enc"))

        Using outFs As IO.FileStream = New IO.FileStream(outFile, IO.FileMode.Create)

            outFs.Write(LenK, 0, 4)
            outFs.Write(LenIV, 0, 4)
            outFs.Write(keyEncrypted, 0, lKey)
            outFs.Write(rjndl.IV, 0, lIV)

            Using outStreamEncrypted As CryptoStream = New CryptoStream(outFs, transform, CryptoStreamMode.Write)

                Dim count As Integer = 0
                Dim offset As Integer = 0

                Dim blockSizeBytes As Integer = (rjndl.BlockSize / 8)
                Dim data() As Byte = New Byte((blockSizeBytes) - 1) {}
                Dim bytesRead As Integer = 0

                Using inFs As IO.FileStream = New IO.FileStream(inFile.FullName, IO.FileMode.Open)
                    Do
                        count = inFs.Read(data, 0, blockSizeBytes)
                        offset += count
                        outStreamEncrypted.Write(data, 0, count)
                        bytesRead = (bytesRead + blockSizeBytes)
                    Loop Until (count = 0)

                    outStreamEncrypted.FlushFinalBlock()
                    inFs.Close()
                End Using
                outStreamEncrypted.Close()
            End Using
            outFs.Close()
        End Using
    End Sub

    Private Sub btnDecryptFile_Click(sender As Object, e As RoutedEventArgs) Handles btnDecryptFile.Click
        If rsa Is Nothing Then
            MsgBox("Key not set.")
        Else
            Dim openFileDialog As New OpenFileDialog
            openFileDialog.InitialDirectory = EncrFolder
            If openFileDialog.ShowDialog Then
                Try
                    Dim fName As String = openFileDialog.FileName
                    If Not String.IsNullOrEmpty(fName) Then
                        Dim fi As FileInfo = New FileInfo(fName)
                        Dim name As String = fi.Name
                        DecryptFile(name)
                    End If
                Catch ex As Exception
                    MessageBox.Show(ex.Message)
                End Try
            End If
        End If
    End Sub

    Private Sub DecryptFile(inFile As String)
        Dim rjndl As New RijndaelManaged
        rjndl.KeySize = 256
        rjndl.BlockSize = 256
        rjndl.Mode = CipherMode.CBC

        Dim LenK() As Byte = New Byte(4 - 1) {}
        Dim LenIV() As Byte = New Byte(4 - 1) {}

        Dim outFile As String = (DecrFolder + (inFile.Substring(0, inFile.LastIndexOf(".")) + ".txt"))

        Using inFs As FileStream = New FileStream((EncrFolder + inFile), FileMode.Open)

            inFs.Seek(0, SeekOrigin.Begin)
            inFs.Read(LenK, 0, 3)
            inFs.Seek(4, SeekOrigin.Begin)
            inFs.Read(LenIV, 0, 3)

            Dim lengthK As Integer = BitConverter.ToInt32(LenK, 0)
            Dim lengthIV As Integer = BitConverter.ToInt32(LenIV, 0)
            Dim startC As Integer = (lengthK + lengthIV + 8)
            Dim lenC As Integer = (CType(inFs.Length, Integer) - startC)
            Dim KeyEncrypted() As Byte = New Byte(lengthK - 1) {}
            Dim IV() As Byte = New Byte(lengthIV - 1) {}

            inFs.Seek(8, SeekOrigin.Begin)
            inFs.Read(KeyEncrypted, 0, lengthK)
            inFs.Seek(8 + lengthK, SeekOrigin.Begin)
            inFs.Read(IV, 0, lengthIV)
            Dim KeyDecrypted() As Byte = rsa.Decrypt(KeyEncrypted, False)

            Dim transform As ICryptoTransform = rjndl.CreateDecryptor(KeyDecrypted, IV)

            Using outFs As FileStream = New FileStream(outFile, FileMode.Create)
                Dim count As Integer = 0
                Dim offset As Integer = 0

                Dim blockSizeBytes As Integer = (rjndl.BlockSize / 8)
                Dim data() As Byte = New Byte(blockSizeBytes - 1) {}

                inFs.Seek(startC, SeekOrigin.Begin)
                Using outStreamDecrypted As CryptoStream = New CryptoStream(outFs, transform, CryptoStreamMode.Write)
                    Do
                        count = inFs.Read(data, 0, blockSizeBytes)
                        offset += count
                        outStreamDecrypted.Write(data, 0, count)
                    Loop Until (count = 0)

                    outStreamDecrypted.FlushFinalBlock()
                    outStreamDecrypted.Close()
                End Using
                outFs.Close()
            End Using
            inFs.Close()
        End Using
    End Sub

    Private Sub btnExportPublicKey_Click(sender As Object, e As RoutedEventArgs) Handles btnExportPublicKey.Click
        Dim sw As StreamWriter = New StreamWriter(PubkeyFile)
        sw.Write(rsa.ToXmlString(False))
        sw.Close()
    End Sub

    Private Sub btnImportPublicKey_Click(sender As Object, e As RoutedEventArgs) Handles btnImportPublicKey.Click
        Dim sr As StreamReader = New StreamReader(PubkeyFile)
        cspp.KeyContainerName = keyName
        rsa = New RSACryptoServiceProvider(cspp)
        Dim keytxt As String = sr.ReadToEnd
        rsa.FromXmlString(keytxt)
        rsa.PersistKeyInCsp = True
        If rsa.PublicOnly Then
            label1.Content = "Key: " + cspp.KeyContainerName + " - Public Only"
        Else
            label1.Content = "Key: " + cspp.KeyContainerName + " - Full Key Pair"
        End If
        sr.Close()
    End Sub

    Private Sub btnGetPrivateKey_Click(sender As Object, e As RoutedEventArgs) Handles btnGetPrivateKey.Click
        cspp.KeyContainerName = keyName
        rsa = New RSACryptoServiceProvider(cspp)
        rsa.PersistKeyInCsp = True
        If rsa.PublicOnly Then
            label1.Content = "Key: " + cspp.KeyContainerName + " - Public Only"
        Else
            label1.Content = "Key: " + cspp.KeyContainerName + " - Full Key Pair"
        End If
    End Sub

End Class
