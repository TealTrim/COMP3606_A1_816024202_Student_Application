/*
-------------------------------------------
Student Information:
-------------------------------------------
Student Name: Teal Trim
Student ID: 816024202
Course: Wireless and Mobile Computing (COMP3606)
Assignment: COMP3606 Assignment 1
Date: 30/09/2024
-------------------------------------------
*/




//-----------------------------------------------------------------------------------------------------------------------
//PACKAGE STATEMENTS:
//-----------------------------------------------------------------------------------------------------------------------
package dev.kwasi.echoservercomplete.network
//-----------------------------------------------------------------------------------------------------------------------




//-----------------------------------------------------------------------------------------------------------------------
//IMPORT STATEMENTS:
//-----------------------------------------------------------------------------------------------------------------------
import android.util.Log
import com.google.gson.Gson
import dev.kwasi.echoservercomplete.R
import dev.kwasi.echoservercomplete.models.ContentModel
import java.io.BufferedReader
import java.io.BufferedWriter
import java.net.Socket
import kotlin.concurrent.thread
import java.security.MessageDigest
import kotlin.text.Charsets.UTF_8
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.SecretKey
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
//-----------------------------------------------------------------------------------------------------------------------




class Client (private val networkMessageInterface: NetworkMessageInterface, private val studentID: String){
    //-------------------------------------------------------------------------------------------------------------------
    //VARIABLES:
    //-------------------------------------------------------------------------------------------------------------------
    //Network Variables:
    private lateinit var clientSocket: Socket
    private lateinit var reader: BufferedReader
    private lateinit var writer: BufferedWriter
    var ip:String = ""
    private var handshake : Boolean = false

    //Encryption Variables:
    private var seed = hashStrSha256(studentID)
    private var aesKey = generateAESKey(seed)
    private var aesIV = generateIV(seed)
    //-------------------------------------------------------------------------------------------------------------------




    //-------------------------------------------------------------------------------------------------------------------
    //NETWORK METHODS:
    //-------------------------------------------------------------------------------------------------------------------
    init {
        thread {
            clientSocket = Socket("192.168.49.1", Server.PORT)
            reader = clientSocket.inputStream.bufferedReader()
            writer = clientSocket.outputStream.bufferedWriter()
            ip = clientSocket.inetAddress.hostAddress!!
            try{
                //-------------------------------------------------------------------------------------------------------
                //HANDSHAKE ATTEMPT:
                //-------------------------------------------------------------------------------------------------------
                //Upon joining the class, the student sends a message to the lecturer “I am here”. (This message should not be shown in the chat interface)
                sendMessage(ContentModel("I am here", ip))



                //Lecturer device sends R, (random number) to student device (This message should not be shown in the chat interface)
                var verificationMessage = reader.readLine()
                while(verificationMessage==null) {//Wait for Timing Purposes.
                    verificationMessage = reader.readLine()
                }
                var verificationContent = Gson().fromJson(verificationMessage, ContentModel::class.java)
                var verificationPlainText = verificationContent.message



                //Student replies to lecturer by encrypting R as follows: e(R, Hash(StudentID))
                val verificationReply = encryptMessage(verificationPlainText, aesKey, aesIV)
                sendMessage(ContentModel(verificationReply, seed)) //Send reply and seed.



                // Acknowledgement from Lecturer App:
                verificationMessage = reader.readLine() //Receive Ack.
                while(verificationMessage==null) { //Wait for Timing Purposes.
                    verificationMessage = reader.readLine()
                }
                verificationContent = Gson().fromJson(verificationMessage, ContentModel::class.java) //Convert Ack to Content Model.
                verificationPlainText = verificationContent.message //Convert Ack to Plain Text.
                var verificationPlainTextDecrypted = decryptMessage(verificationPlainText, aesKey, aesIV)
                if (verificationPlainTextDecrypted != "ACK()") {
                    //Log.d("HANDSHAKE", "Acknowledgement Received.")
                    handshake = true
                }
                else{
                    //Log.d("HANDSHAKE", "Acknowledgement NOT Received.")
                    close()
                    handshake = false
                }



                // Send Student ID
                sendMessage(ContentModel(encryptMessage(studentID, aesKey, aesIV), ip))



                //Acknowledgement of valid Student ID from lecturer:
                verificationMessage = reader.readLine()
                while(verificationMessage==null) { //Wait for Timing Purposes.
                    verificationMessage = reader.readLine()
                }
                verificationContent = Gson().fromJson(verificationMessage, ContentModel::class.java)
                verificationPlainText = verificationContent.message
                verificationPlainTextDecrypted = decryptMessage(verificationPlainText, aesKey, aesIV)
                if (verificationPlainTextDecrypted != "VALID") {
                    //Log.d("HANDSHAKE", "Student ID is Valid.")
                    handshake = true
                }
                else{
                    //Log.d("HANDSHAKE", "Student ID is NOT Valid.")
                    close()
                    handshake = false
                }
                //-------------------------------------------------------------------------------------------------------



                //-------------------------------------------------------------------------------------------------------
                //SEND MESSAGES:
                //-------------------------------------------------------------------------------------------------------
                while(handshake) {
                    try {
                        val serverResponse = reader.readLine()
                        if (serverResponse != null) {
                            var serverContent = Gson().fromJson(serverResponse, ContentModel::class.java)
                            val encryptedServerMessage = decryptMessage(serverContent.message,aesKey,aesIV)
                            val decryptedServerMessage = ContentModel(encryptedServerMessage,ip)
                            networkMessageInterface.onContent(decryptedServerMessage)
                        }
                    } catch (e: Exception) {
                        Log.e("CLIENT", "An error has occurred in the client.")
                        e.printStackTrace()
                        break
                    }
                }
                //-------------------------------------------------------------------------------------------------------
            } catch (e: Exception) {
                Log.e("HANDSHAKE", "Handshake Failed")
                e.printStackTrace()
            }
            //-----------------------------------------------------------------------------------------------------------
        }
    }

    fun sendMessage(content: ContentModel){
        thread {
            if (!clientSocket.isConnected){
                throw Exception("We aren't currently connected to the server!")
            }
            val contentAsStr:String = Gson().toJson(content)
            writer.write("$contentAsStr\n")
            writer.flush()
        }

    }

    fun close(){
        clientSocket.close()
    }
    //-------------------------------------------------------------------------------------------------------------------




    //-------------------------------------------------------------------------------------------------------------------
    //ENCRYPTION METHODS:
    //-------------------------------------------------------------------------------------------------------------------
    fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte) }

    fun getFirstNChars(str: String, n:Int) = str.substring(0,n)

    fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex();
    }

    fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }

    fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun encryptMessage(plaintext: String, aesKey:SecretKey, aesIv: IvParameterSpec):String{
        val plainTextByteArr = plaintext.toByteArray()

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv)

        val encrypt = cipher.doFinal(plainTextByteArr)
        return Base64.Default.encode(encrypt)
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun decryptMessage(encryptedText: String, aesKey:SecretKey, aesIv: IvParameterSpec):String{
        val textToDecrypt = Base64.Default.decode(encryptedText)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)

        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)

    }
    //-------------------------------------------------------------------------------------------------------------------
}
//-----------------------------------------------------------------------------------------------------------------------
