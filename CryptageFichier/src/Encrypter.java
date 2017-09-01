import java.io.BufferedOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



public class Encrypter
{

	public static String MASTER_KEY="WTdg2>ug2G{9.L8S";
	public static String KEY;
	public static String KEY_TIP;
	public static Preferences pref =  Preferences.userNodeForPackage( Encrypter.class );
	public static Thread printStateThread;
	public static boolean running;
	public static double totalSize;
	public static double current=0;

	public static final int PACKET_SIZE = (int)Math.pow(2, 20);

	public static void encrypt(File f, String root, String mdp) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException
	{
		Cipher encrCipher=initCipher(Cipher.ENCRYPT_MODE, mdp);

		String name;
		try
		{
			byte[] nameBA = f.getName().getBytes();
			byte[] encrNameBA = encrCipher.doFinal(nameBA);
			encrNameBA = Base64.getEncoder().encode(encrNameBA);
			String fileName=new String(encrNameBA);
			fileName = fileName.replaceAll("\\\\", URLEncoder.encode("\\","UTF-8"));
			fileName = fileName.replaceAll("/", URLEncoder.encode("/","UTF-8"));
			fileName = fileName.replaceAll("=", URLEncoder.encode("=","UTF-8"));
			name = root+"/"+fileName;
		}
		catch(BadPaddingException | IllegalBlockSizeException e)
		{
			name = root+"/"+f.getName();
		}
		File f2 = new File(name);
		if (f.isDirectory())
		{
			for (File ff : f.listFiles())
			{
				encrypt(ff,f.getAbsolutePath(), mdp);
			}
			Files.move(f.toPath(), f2.toPath());
		}
		else
		{
			FileInputStream fis = new FileInputStream(f);
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(f2,false));
			DataOutputStream dos = new DataOutputStream(bos);
			byte[] data=new byte[PACKET_SIZE];
			while (fis.read(data)!=-1)
			{
				byte[] encryptedFile = null;
				try
				{
					encryptedFile = encrCipher.doFinal(data);
				} catch (Exception e)
				{
					e.printStackTrace();
				}
				dos.writeInt(encryptedFile.length);
				for (int i=0;i<encryptedFile.length;i++)
				{
					dos.write(encryptedFile[i]);
					current+=1;
				}
			}
			dos.writeInt(-1);
			fis.close();
			bos.close();

			Files.delete(f.toPath());
		}
	}

	public static void decrypt(File f, String root, String mdp) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException
	{

		Cipher desCipher=initCipher(Cipher.DECRYPT_MODE, mdp);

		String name;
		try
		{
			String fileName=f.getName();
			fileName = fileName.replaceAll(URLEncoder.encode("=","UTF-8"), "=");
			fileName = fileName.replaceAll(URLEncoder.encode("/","UTF-8"), "/");
			fileName = fileName.replaceAll(URLEncoder.encode("\\","UTF-8"), "\\");
			byte[] desNameBA = Base64.getDecoder().decode(fileName.getBytes());
			desNameBA = desCipher.doFinal(desNameBA);
			fileName=new String(desNameBA);
			fileName = fileName.replaceAll("\\\\", URLEncoder.encode("\\","UTF-8"));
			fileName = fileName.replaceAll("/", URLEncoder.encode("/","UTF-8"));
			fileName = fileName.replaceAll("=", URLEncoder.encode("=","UTF-8"));
			name = root+"/"+fileName;
		}
		catch (Exception e)
		{
			name = root + "/" + f.getName();
		}
		File f2 = new File(name);

		if (f.isDirectory())
		{
			for (File ff : f.listFiles())
			{
				decrypt(ff, f.getAbsolutePath(),  mdp);
			}
			Files.move(f.toPath(), f2.toPath());
		}
		else
		{
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(f2,false));
			int sz;
			byte[] decryptedFile = null;
			while ((sz=dis.readInt())!=-1)
			{
				byte[] data = new byte[sz];
				dis.readFully(data);
				try
				{
					decryptedFile = desCipher.doFinal(data);
				} catch (BadPaddingException e)
				{
					e.printStackTrace();
				}
				for (int i=0;i<decryptedFile.length;i++)
				{
					bos.write(decryptedFile[i]);
					current+=1;
				}
			}

			fis.close();
			bos.close();

			Files.delete(f.toPath());
		}
	}

	public static void printAvancement()
	{
		System.out.print("\rAvancement : "+(int)(current*100/totalSize)+"%                       \r");
	}

	private static int totalLength(File f)
	{
		int size=0;
		if (!f.isDirectory())
		{
			return (int)f.length();
		}
		else
		{
			for (File ff : f.listFiles())
			{
				size+=totalLength(ff);
			}
		}
		return size;
	}

	private static SecretKeySpec initSecretKey(String password) throws UnsupportedEncodingException, NoSuchAlgorithmException
	{
			byte[] key = password.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			return new SecretKeySpec(key, "AES");
	}
	
	private static Cipher initCipher(int mode, String mdp) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException
	{
		SecretKeySpec skeySpec = initSecretKey(mdp);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(mode, skeySpec);
		return cipher;
	}
	
	private static void changePassword(Console c, Cipher encrCipher) throws IllegalBlockSizeException, BadPaddingException
	{
		System.out.println("Choisissez un mot de passe : (au moins 8 caractères)");
		char[] newPass=c.readPassword();
		while (newPass.length<8)
		{
			System.out.println("Mot de passe trop court !");
			System.out.println("Choisissez un mot de passe : (au moins 8 caractères)");
			newPass = c.readPassword();
		}
		System.out.println("Confirmez votre mot de passe :");
		char[] confirmNewPass=c.readPassword();

		while (!new String(newPass).equals(new String(confirmNewPass)))
		{
			System.out.println("Les mots de passes ne sont pas identiques !");
			System.out.println("Choisissez un mot de passe : (au moins 8 caractères)");
			newPass = c.readPassword();
			System.out.println("Confirmez votre mot de passe :");
			confirmNewPass=c.readPassword();
		}
		KEY=new String(newPass);

		System.out.println("Ecrivez une phrase de rappel de votre mot de passe :");
		KEY_TIP=c.readLine();
		
		pref.putByteArray("password",encrCipher.doFinal(KEY.getBytes()));
		pref.put("tip", KEY_TIP);
	}
	
	private static void initPrintStateThread()
	{
		printStateThread=new Thread(new Runnable()
		{

			@Override
			public void run()
			{
				System.out.print("Avancement : 0%");
				while (running)
				{
					printAvancement();
					try
					{
						Thread.sleep(100);
					} catch (InterruptedException e)
					{
						e.printStackTrace();
					}
				}
			}
		});
	}
	
	public static void main(String[] args) throws InterruptedException, BackingStoreException
	{
		try
		{
			new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
		} catch (IOException e1) {}

		Console c = System.console();

		try
		{
			Cipher desCipher=initCipher(Cipher.DECRYPT_MODE, MASTER_KEY);
			Cipher encrCipher=initCipher(Cipher.ENCRYPT_MODE, MASTER_KEY);

			byte[] encrKEY = pref.getByteArray("password", null);
			if (encrKEY==null)
			{
				changePassword(c,encrCipher);
			}
			else
			{
				KEY=new String(desCipher.doFinal(encrKEY));
			}
		} catch (Exception e)
		{
			System.out.println("ERREUR INCONNUE : "+e.getMessage());
			Thread.sleep(10000);
			System.exit(0);
		}
		
		if (args.length!=2)
		{
			System.out.println("Encrypter : ");
			System.out.println("1er argument : Mode, E pour encrypter, D pour décrypter.");
			System.out.println("2e argument  : Fichier, écrire le chemin vers le fichier à encrypter/décrypter.");
			Thread.sleep(10000);
			System.exit(0);
		}

		boolean encrMode=false;
		switch (args[0])
		{
		case "d":
			break;
		case "D":
			break;
		case "e":
			encrMode=true;
			break;
		case "E":
			encrMode=true;
			break;
		default:
			System.exit(0);
		}

		File f=new File(args[1]);

		System.out.println("*************************************************************");
		if (encrMode)
			System.out.println("ENCRYPTAGE DU FICHIER : "+f.getName());
		else
			System.out.println("DECRYPTAGE DU FICHIER : "+f.getName());
		System.out.println("*************************************************************");
		System.out.println("");

		System.out.println("Mot de passe ? (R pour un rappel)");
		String key = new String(c.readPassword());

		if (key.equals("R") || key.equals("r"))
		{
			System.out.println(KEY_TIP);
			System.out.println("Mot de passe ?");
			key = new String(c.readPassword());
		}


		while (!key.equals(KEY))
		{
			if (key.equals("R") || key.equals("r"))
				System.out.println(KEY_TIP);
			else
				System.out.println("Mauvais mot de passe !");

			System.out.println("Mot de passe ?");
			key = new String(c.readPassword());
		}


		try
		{
			running=true;

			totalSize=totalLength(f);
			initPrintStateThread();
			printStateThread.start();
			if (args[0].equals("E") || args[0].equals("e")) encrypt(f,f.getParent(),KEY);
			else if (args[0].equals("D")) decrypt(f,f.getParent(), KEY);
			else System.exit(0);
		}
		catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException e)
		{
			e.printStackTrace();
			Thread.sleep(10000);
		} catch (IllegalBlockSizeException e)
		{
			running=false;
			System.out.println("\rVotre fichier est déjà décrypté.           \r");
			Thread.sleep(2000);
		}
		running=false;
		Thread.sleep(10);
		System.out.println(((args[0].equals("E") || args[0].equals("e"))?"Encryptage":"Décryptage")+" Réussi !");
		Thread.sleep(800);
	}

}
