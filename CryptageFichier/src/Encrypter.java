import java.io.BufferedOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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
	public static Thread printStateThread,printAnalysisThread, countFilesThread;
	public static boolean running;
	public static double totalSize;
	public static double current=0;
	public static String mdp,tip,log="";
	public static boolean nToAll=false;
	public static Console c = System.console();
	public static Cipher MASTERdesCipher;
	public static Cipher MASTERencrCipher;
	public static List<String> tips = new ArrayList<>();
	public static List<String> nonCryptedFiles=new ArrayList<>();
	public static int nbFail,nbFile;
	public static int totalFilesToScan=0,currentFileScanned=0;

	public static String TAG = "CryptedByMyEncrypterTool";
	public static String ENCRYPTED_TAG;
	public static final int PACKET_SIZE = (int)Math.pow(2, 20);

	public static void encrypt(File f) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, CantEncryptException, ZipException
	{
		if (f.getName().endsWith(".zip") || f.getName().endsWith(".7z") || f.getName().endsWith(".jar"))
			throw new ZipException();
		Cipher encrCipher=initCipher(Cipher.ENCRYPT_MODE, mdp);
		String name;
		String root=f.getParent();
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
				encrypt(ff);
			}
			Files.move(f.toPath(), f2.toPath());
		}
		else
		{
			FileInputStream fis = new FileInputStream(f);
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(f2,false));
			DataOutputStream dos = new DataOutputStream(bos);

			try
			{
				dos.write(ENCRYPTED_TAG.getBytes());
				byte[] encrTip=MASTERencrCipher.doFinal(tip.getBytes());
				dos.writeInt(encrTip.length);
				dos.write(encrTip);
			} catch (IllegalBlockSizeException | BadPaddingException e1)
			{
				fis.close();
				dos.close();
				throw new CantEncryptException();
			}
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

	public static void decrypt(File f) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException, EOFException, BadPaddingException
	{
		Cipher desCipher=initCipher(Cipher.DECRYPT_MODE, mdp);
		boolean ok=true;
		String name;
		String root=f.getParent();
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
			ok=false;
			name = root + "/" + f.getName()+"tmp";
		}
		File f2 = new File(name);

		if (f.isDirectory())
		{
			for (File ff : f.listFiles())
			{
				if (nonCryptedFiles.contains(ff.getAbsolutePath()))
					continue;
				if (!ff.isDirectory())
					nbFile++;
				try {
					decrypt(ff);
				} catch (Exception e)
				{
					nbFail++;
				}
			}
			if (ok)
				Files.move(f.toPath(), f2.toPath());
		}
		else
		{
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(f2,false));
			int sz;
			byte[] decryptedFile = null;
			try
			{
				byte[] tagArray = new byte[ENCRYPTED_TAG.length()];
				dis.readFully(tagArray);
				MASTERdesCipher.doFinal(tagArray);
				int tipSz=dis.readInt();
				dis.readFully(new byte[tipSz]);
				while ((sz=dis.readInt())!=-1)
				{
					byte[] data = new byte[sz];
					dis.readFully(data);
					decryptedFile = desCipher.doFinal(data);
					for (int i=0;i<decryptedFile.length;i++)
					{
						bos.write(decryptedFile[i]);
						current+=1;
					}
				}
			} catch (EOFException e)
			{
				ok=false;
				throw new EOFException();
			} catch (NegativeArraySizeException e)
			{
				ok=false;
				throw new NegativeArraySizeException();
			} finally {
				dis.close();
				bos.close();
				if (ok)
				{
					Files.delete(f.toPath());
				}
				else
				{
					Files.delete(f2.toPath());
				}
			}
		}
	}

	public static void printAvancement()
	{
		System.out.print("\rAvancement : "+(int)(current*100/totalSize)+"%                       \r");
	}

	private static double totalLength(File f)
	{
		if (nonCryptedFiles.contains(f.getAbsolutePath()))
			return 0;
		int size=0;
		if (!f.isDirectory())
		{
			return f.length();
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

	private static void changePassword(Cipher encrCipher)
	{
		String newPass = null, confirmNewPass;
		boolean ok=false;
		while (!ok)
		{
			ok=true;
			System.out.println("Choisissez un mot de passe MyEncripterTool : (au moins 8 caractères)");
			newPass =  new String(c.readPassword());
			if (newPass.length()<8)
			{
				ok=false;
				System.out.println("Mot de passe trop court !");
			}
			else
			{
				System.out.println("Confirmez votre mot de passe :");
				confirmNewPass=new String(c.readPassword());
				if (!newPass.equals(confirmNewPass))
				{
					ok=false;
					System.out.println("Mots de passe saisis différent.");
				}
			}
		}
		KEY=new String(newPass);

		System.out.println("Ecrivez une phrase de rappel de votre mot de passe MyEncripterTool :");
		KEY_TIP=c.readLine();

		try
		{
			pref.putByteArray("password",encrCipher.doFinal(KEY.getBytes()));
		} catch (IllegalBlockSizeException | BadPaddingException e)
		{
			System.out.println("Echec du changement de mot de passe.");
			try
			{
				Thread.sleep(2000);
			} catch (InterruptedException e1)
			{
				e1.printStackTrace();
			}
			System.exit(0);
		}
		pref.put("tip", KEY_TIP);
		System.out.println("Nouveau mot de passe enregistré.");
	}

	private static void initPrintAnalysesThread()
	{
		printAnalysisThread=new Thread(new Runnable()
		{

			@Override
			public void run()
			{
				System.out.println("");
				System.out.print("\rAnalyse des fichiers en cours : "+currentFileScanned+"/"+totalFilesToScan+"\r");
				while (running)
				{
					System.out.print("\rAnalyse des fichiers en cours : "+currentFileScanned+"/"+totalFilesToScan+"                       \r");
					try
					{
						Thread.sleep(5);
					} catch (InterruptedException e)
					{
						e.printStackTrace();
					}
				}
			}
		});
	}

	private static void initCountFilesThread(String[] args)
	{
		countFilesThread=new Thread(new Runnable()
		{

			@Override
			public void run()
			{
				nbFile(args);
			}
		});
	}

	private static void initPrintStateThread()
	{
		printStateThread=new Thread(new Runnable()
		{

			@Override
			public void run()
			{
				System.out.println("");
				System.out.print("\rAvancement : 0%\r");
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

	private static void printStart(String[] args, boolean encrMode)
	{
		System.out.println("*************************************************************");
		if (args.length==2)
		{
			File f = new File(args[1]);
			if (encrMode)
				System.out.println("ENCRYPTAGE DU FICHIER : \n     - "+f.getAbsolutePath());
			else
				System.out.println("DECRYPTAGE DU FICHIER : \n     - "+f.getAbsolutePath());
		}
		else
		{
			if (encrMode)
				System.out.println("ENCRYPTAGE DES FICHIERS : ");
			else
				System.out.println("DECRYPTAGE DES FICHIERS : ");
			for (int i = 1 ; i < args.length ; i++)
			{
				File f = new File(args[i]);
				System.out.println("     - "+f.getAbsolutePath());
			}
		}
		System.out.println("*************************************************************");
		System.out.println("");
	}

	public static void main(String[] args) throws InterruptedException, BackingStoreException, IOException
	{
		try
		{
			new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
		} catch (IOException e1) {}

		try
		{
			MASTERdesCipher=initCipher(Cipher.DECRYPT_MODE, MASTER_KEY);
			MASTERencrCipher=initCipher(Cipher.ENCRYPT_MODE, MASTER_KEY);
			ENCRYPTED_TAG=new String(MASTERencrCipher.doFinal(TAG.getBytes()));
			byte[] encrKEY = pref.getByteArray("password", null);
			if (encrKEY==null)
			{
				changePassword(MASTERencrCipher);
			}
			else
			{
				KEY_TIP=pref.get("tip",null);
				KEY=new String(MASTERdesCipher.doFinal(encrKEY));
			}
		} catch (Exception e)
		{
			System.out.println("ERREUR INCONNUE : "+e.getMessage());
			Thread.sleep(10000);
			System.exit(0);
		}

		if (args.length<2)
		{
			System.out.println("Encrypter : ");
			System.out.println("1er argument : Mode, E pour encrypter, D pour décrypter.");
			System.out.println("autres arguments  : Fichier(s), écrire le(s) chemin(s) vers le(s) fichier(s) à encrypter/décrypter.");
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

		printStart(args,encrMode);



		boolean mdpOk=false;
		while (!mdpOk)
		{
			mdpOk=true;
			System.out.println("Mot de passe MyEncripterTool? (R pour un rappel, C pour modifier)");
			String key = new String(c.readPassword());

			if (!key.equals(KEY))
			{
				mdpOk=false;
				if (key.equals("R") || key.equals("r"))
					System.out.println(KEY_TIP);
				else if (key.equals("C") || key.equals("c"))
				{
					boolean modif=false;
					while (!modif)
					{
						modif=true;
						System.out.println("Ancien mot de passe? (R pour un rappel)");
						String oldPass = new String(c.readPassword());
						if (!oldPass.equals(KEY))
						{
							modif=false;
							if (oldPass.equals("R") || oldPass.equals("r"))
								System.out.println(KEY_TIP);
							else
							{
								System.out.println("Mot de passe invalide.");
							}
						}
					}
					changePassword(MASTERencrCipher);
				}
				else
					System.out.println("Mot de passe invalide.");
			}
		}

		String confirm;
		if (args[0].equals("E") || args[0].equals("e")) 
		{
			mdpOk=false;
			while (!mdpOk)
			{
				mdpOk=true;
				System.out.println("Mot de passe à appliquer à ce(s) fichier(s) (Au moins 6 caractères) :");
				mdp = new String(c.readPassword());
				if (mdp.length()<6)
				{
					mdpOk=false;
					System.out.println("Mot de passe trop court.");
				}
				else
				{
					System.out.println("Confirmer ce mot de passe :");
					confirm=new String(c.readPassword());
					if (!mdp.equals(confirm))
					{
						mdpOk=false;
						System.out.println("Mots de passe saisis différents.");
					}
				}
			}
			System.out.println("Ecrivez une phrase de rappel de votre mot de passe pour ce(s) fichier(s) :");
			tip=c.readLine();
		}
		else if (args[0].equals("D")) 
		{
			initCountFilesThread(args);
			initPrintAnalysesThread();
			running=true;
			countFilesThread.start();
			printAnalysisThread.start();
			Thread.sleep(10);

			generateTipsAndNonCryptedFilesList(args);
			running=false;

			Thread.sleep(100);

			if (tips.isEmpty())
			{
				System.out.println("Ce(s) fichier(s) ne sont pas encryptés.");
				Thread.sleep(2000);
				System.exit(0);
			}
			boolean mdpChoisi=false;
			while (!mdpChoisi)
			{
				mdpChoisi=true;
				System.out.println("Mot de passe pour dévérouiller ce(s) fichier(s) ? (R pour des rappels)");
				mdp = new String(c.readPassword());
				if (mdp.equals("r") || mdp.equals("R"))
				{
					mdpChoisi=false;
					for (String t : tips)
						System.out.println(" - "+t);
				}
			}
		}
		else 
		{
			System.out.println("Ordre invalide (ni Decrypt, ni Encrypt).");
			Thread.sleep(2000);
			System.exit(0);
		}

		for (int i=1;i<args.length;i++)
		{
			File f = new File(args[i]);
			String fileName = f.getName();
			if (!nonCryptedFiles.contains(f.getAbsolutePath()))
			{
				nbFile=0;
				nbFail=0;
				running=true;
				totalSize=totalLength(f);
				current=0;
				initPrintStateThread();
				printStateThread.start();
				Thread.sleep(10);
				boolean success=doAction(args,f);

				Thread.sleep(10);
				if (!f.isDirectory())
					System.out.println(((args[0].equals("E") || args[0].equals("e"))?"Encryptage":"Décryptage")+(success?" Réussi : ":" Echoué : ")+ fileName +" "+log);
				else
					System.out.println(((args[0].equals("E") || args[0].equals("e"))?"Encryptage":"Décryptage")+" Réussi : "+"("+(nbFile-nbFail)+"/"+nbFile+") : "+ fileName);
				Thread.sleep(150);
			}
		}
		Thread.sleep(2000);
	}

	private static List<String> getTipFromFile(File f)
	{
		List<String> tips=new ArrayList<>();
		String tip=null;
		if (!f.isDirectory())
		{
			try
			{
				currentFileScanned++;
				FileInputStream fis = new FileInputStream(f);
				DataInputStream dis = new DataInputStream(fis);
				byte[] tagArray = new byte[ENCRYPTED_TAG.length()];
				dis.readFully(tagArray);
				MASTERdesCipher.doFinal(tagArray);
				int tipSz=dis.readInt();
				byte[] tipArrayEncr;
				try{
					tipArrayEncr=new byte[tipSz];
				} catch (OutOfMemoryError e)
				{
					throw new Exception();
				}
				dis.readFully(tipArrayEncr);
				byte[] tipArray = MASTERdesCipher.doFinal(tipArrayEncr);
				tip=new String(tipArray);
				fis.close();
				dis.close();
				tips.add(tip);
			} catch (Exception e) {
				if (!nonCryptedFiles.contains(f.getAbsolutePath()))
					nonCryptedFiles.add(f.getAbsolutePath());
			}
		}
		else
		{
			currentFileScanned++;
			for (File ff : f.listFiles())
				for (String str : getTipFromFile(ff))
					tips.add(str);
			if (tips.isEmpty() && !nonCryptedFiles.contains(f.getAbsolutePath()))
				nonCryptedFiles.add(f.getAbsolutePath());
		}
		return tips;
	}

	private static boolean doAction(String[] args, File f) throws InterruptedException, IOException
	{
		boolean success=true;
		try
		{
			if (args[0].equals("E") || args[0].equals("e")) 
				encrypt(f);
			else if (args[0].equals("D")) 
				decrypt(f);
		} catch (ZipException e) {
			success=false;
			running=false;
			log=e.getMessage();
		} catch (BadPaddingException e)
		{
			success=false;
			running=false;
			success = retryDecrypt(f,args);
		} catch (NegativeArraySizeException | IllegalBlockSizeException | EOFException e)
		{
			success=false;
			running=false;
			log="Fichier est déjà décrypté.";
		} catch(InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException | CantEncryptException e)
		{
			success=false;
			running=false;
			log=e.getMessage();
		}
		running=false;
		if (!nToAll && nbFile!=0 && nbFail==nbFile)
		{
			success = retryDecrypt(f, args);
		}
		if (success)
			log="";
		Thread.sleep(150);
		return success;
	}

	private static boolean retryDecrypt(File f, String[] args) throws InterruptedException, IOException
	{
		List<String> tips=getTipFromFile(f);

		log="Mot de passe invalide.";
		if (!nToAll && (args[0].equals("d") || args[0].equals("D")))
		{
			System.out.println("Mot de passe invalide, en essayer un autre ? (o/n)");
			String retry=c.readLine();
			if (retry.equals("o") || retry.equals("O"))
			{
				boolean mdpChoisi=false;
				while (!mdpChoisi)
				{
					mdpChoisi=true;	
					System.out.println("Nouveau mot de passe : (R pour un rappel)");
					mdp = new String(c.readPassword());
					if (mdp.equals("r") || mdp.equals("R"))
					{
						mdpChoisi=false;
						for (String tip : tips)
							System.out.println(" - "+tip);
					}
				}
				return doAction(args, f);
			}
			else if (retry.equals("n") || retry.equals("N"))
			{
				System.out.println("Redemander en cas d'erreur pour les autres fichiers ? (o/n)");
				String noForever=c.readLine();
				if (noForever.equals("o") || noForever.equals("O"))
					nToAll=false;
				else
					nToAll=true;
			}
		}
		return false;
	}

	private static void generateTipsAndNonCryptedFilesList(String[] args)
	{
		for (int i=1;i<args.length;i++)
		{
			File f=new File(args[i]);
			List<String> fileTips = getTipFromFile(f);
			for (String fileTip : fileTips)
				if (!tips.contains(fileTip))
					tips.add(fileTip);
		}
	}

	private static void nbFile(File f)
	{
		if (!f.isDirectory())
			{
			totalFilesToScan++;
			return;
			}
		for (File ff : f.listFiles())
			nbFile(ff);
	}

	private static void nbFile(String[] args)
	{
		for (int i=1;i<args.length;i++)
			nbFile(new File(args[i]));
	}
}