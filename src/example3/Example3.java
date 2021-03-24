package example3;

/*
 * @description
 * CWE: 256 Plaintext Storage of a Password.  Read the password from a Properties file or a regular file.  In the good case, read the file from the console.
 * BadSource:  Read password from a .properties file (from the property named password)
 * GoodSource: Read password from a .properties file (from the property named password) and then decrypt it
 * Sinks:
 *    GoodSink: Decrypt password and use decrypted password as password to connect to DB
 *    BadSink : Use password as password to connect to DB
 * 
 * */


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.logging.Level;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.util.Properties;

import java.io.FileInputStream;

public class Example3 {




public byte[] getPassword() throws Throwable
    {
        String password;
        byte[] passwordSerialized = null;
        password = ""; /* init password */

        /* retrieve the property */
        Properties properties = new Properties();
        FileInputStream streamFileInput = null;
        try
        {
            streamFileInput = new FileInputStream("../common/config.properties");
            properties.load(streamFileInput);

            password = properties.getProperty("password");
            String encryptedPassword = encryptPassword(password);
            System.out.println(encryptedPassword); //debug
        }
        catch (IOException exceptIO)
        {
            exceptIO.printStackTrace();
        }
        finally
        {
            /* clean up stream reading objects */
            try
            {
                if (streamFileInput != null)
                {
                    streamFileInput.close();
                }
            }
            catch (IOException exceptIO)
            {
            	 exceptIO.printStackTrace();
            }
        }

        /* POTENTIAL FLAW: The raw password read from the .properties file is passed on (without being decrypted) */

        /* serialize password to a byte array */
        ByteArrayOutputStream streamByteArrayOutput = null;
        ObjectOutput outputObject = null;

        try
        {
            streamByteArrayOutput = new ByteArrayOutputStream() ;
            outputObject = new ObjectOutputStream(streamByteArrayOutput) ;
            outputObject.writeObject(password);
            passwordSerialized = streamByteArrayOutput.toByteArray();
            badSink(passwordSerialized  );
        }
        catch (IOException exceptIO)
        {
        	exceptIO.printStackTrace();
        }
        finally
        {
            /* clean up stream writing objects */
            try
            {
                if (outputObject != null)
                {
                    outputObject.close();
                }
            }
            catch (IOException exceptIO)
            {
            	exceptIO.printStackTrace();
            }

            try
            {
                if (streamByteArrayOutput != null)
                {
                    streamByteArrayOutput.close();
                }
            }
            catch (IOException exceptIO)
            {
            	exceptIO.printStackTrace();
            }
        }
        return passwordSerialized;
    }

public static String encryptPassword(String input) 
{ 
    try { 

        // Static getInstance method is called with hashing MD5 
        MessageDigest md = MessageDigest.getInstance("MD5"); 

        // digest() method is called to calculate message digest 
        //  of an input digest() return array of byte 
        byte[] messageDigest = md.digest(input.getBytes()); 

        // Convert byte array into signum representation 
        BigInteger no = new BigInteger(1, messageDigest); 

        // Convert message digest into hex value 
        String hashtext = no.toString(16); 
        while (hashtext.length() < 32) { 
            hashtext = "0" + hashtext; 
        } 
        return hashtext; 
    }  

    // For specifying wrong message digest algorithms 
    catch (NoSuchAlgorithmException e) { 
        throw new RuntimeException(e); 
    } 
} 
    
    public Connection badSink(byte[] passwordSerialized ) throws Throwable
	{
        /* unserialize password */
        ByteArrayInputStream streamByteArrayInput = null;
        ObjectInputStream streamObjectInput = null;
        Connection dBConnection = null;

        try
        {
            streamByteArrayInput = new ByteArrayInputStream(passwordSerialized);
            streamObjectInput = new ObjectInputStream(streamByteArrayInput);
            String password = (String)streamObjectInput.readObject();

            /* POTENTIAL FLAW: Use password as a password to connect to a DB  (without being decrypted) */

            
            try
            {
                dBConnection = DriverManager.getConnection("192.168.105.23", "sa", password);
            }
            catch (SQLException exceptSql)
            {
            	exceptSql.printStackTrace();
            }
            finally
            {
                try
                {
                    if (dBConnection != null)
                    {
                        dBConnection.close();
                    }
                }
                catch (SQLException exceptSql)
                {
                	exceptSql.printStackTrace();
                }
            }

        }
        catch (IOException exceptIO)
        {
            //To DO
        }
        catch (ClassNotFoundException exceptClassNotFound)
        {
            //TO DO
        }
        finally
        {
            /* clean up stream reading objects */
        	
            try
            {
                if (streamObjectInput != null)
                {
                    streamObjectInput.close();
                }
            }
            catch (IOException exceptIO)
            {
            	exceptIO.printStackTrace();

            try
            {
                if (streamByteArrayInput != null)
                {
                    streamByteArrayInput.close();
                }
            }
            catch (IOException exceptIO1)
            {
            	exceptIO1.printStackTrace();
            }
        }
           
        }
        return dBConnection;
    }
    public void badSQL() throws Throwable
    {
        String data;
        Example3 e = new Example3();
        
       
        Connection dBConnection = e.badSink(e.getPassword());
        data = ""; /* Initialize data */

        /* retrieve the property */
        {
            Properties properties = new Properties();
            FileInputStream streamFileInput = null;

            try
            {
                streamFileInput = new FileInputStream("../common/config.properties");
                properties.load(streamFileInput);

                /* POTENTIAL FLAW: Read data from a .properties file */
                data = properties.getProperty("data");
            }
            catch (IOException exceptIO)
            {
            	 System.out.println("Error Will Robinson!");
            }
            finally
            {
                /* Close stream reading object */
                try
                {
                    if (streamFileInput != null)
                    {
                        streamFileInput.close();
                    }
                }
                catch (IOException exceptIO)
                {
                    //todo
                }
            }
        }

        Connection dbConnection = null;
        Statement sqlStatement = null;

        try
        {
            //dbConnection = IO.getDBConnection();
            sqlStatement = dbConnection.createStatement();

            /* POTENTIAL FLAW: data concatenated into SQL statement used in execute(), which could result in SQL Injection */
            Boolean result = sqlStatement.execute("insert into users (status) values ('updated') where name='"+data+"'");

            if(result)
            {
                System.out.println("Name, " + data + ", updated successfully");
            }
            else
            {
            	 System.out.println("Unable to update records for user: " + data);
            }
        }
        catch (SQLException exceptSql)
        {
        	 System.out.println("Error Will Robinson!");
        }
        finally
        {
            try
            {
                if (sqlStatement != null)
                {
                    sqlStatement.close();
                }
            }
            catch (SQLException exceptSql)
            {
            	 System.out.println("Error Will Robinson!");
            }

            try
            {
                if (dbConnection != null)
                {
                    dbConnection.close();
                }
            }
            catch (SQLException exceptSql)
            {
            	 System.out.println("Error Will Robinson!");
            }
        }

    }

   
    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the testcases as one
     * application, which is how source code analysis tools are tested.
     */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
       
    }
}
