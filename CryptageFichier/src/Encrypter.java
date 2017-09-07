import java.io.BufferedOutputStream;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;



public class Encrypter
{

	public static final int DIR=1;
	public static final int FILE=2;
	public static final int NEXTFILE=-1;
	public static final int END=-2;

	public static final int DECRYPT_MODE=1;
	public static final int ENCRYPT_MODE=2;

	public static int MODE;

	public static Preferences pref =  Preferences.userNodeForPackage( Encrypter.class );

	public static final String MASTER_KEY="WTdg2>ug2G{9.L8S";
	public static Cipher MASTERdesCipher;
	public static Cipher MASTERencrCipher;

	public static String KEY;
	public static String KEY_TIP;

	public static String mdp,tip,log="";

	public static Thread printStateThread,printAnalysisThread,countFilesThread;
	public static int nbFail,nbFile;
	public static int totalFilesToScan=0,currentFileScanned=0;
	public static double totalSize,current=0;
	public static boolean running;

	public static boolean nToAll=false;
	public static Console c = System.console();
	public static List<String> tips = new ArrayList<>();
	public static List<String> cryptedFiles=new ArrayList<>();

	public static String TAG = "CryptedByMyEncrypterTool";

	public static final int PACKET_SIZE = (int)Math.pow(2, 20);
	public static final int SMALL_PACKET_SIZE = 1024;
	public static int countToSmallPacketSize=0;

	public static void initEncrypt(File f, File outFile, String pass) throws CantEncryptException, IOException
	{
		try {

			if (f.getName().endsWith(".zip") || f.getName().endsWith(".7z") || f.getName().endsWith(".jar"))
				throw new CantEncryptException();

			int i=0;
			while (outFile.exists())
				outFile=new File(outFile.getAbsolutePath()+" ("+(++i)+")");

			Cipher encrCipher=initCipher(Cipher.ENCRYPT_MODE, pass);
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outFile,false));
			DataOutputStream dos = new DataOutputStream(bos);

			dos.write(TAG.getBytes());

			byte[] encrTip=MASTERencrCipher.doFinal(tip.getBytes());
			dos.writeInt(encrTip.length);
			dos.write(encrTip);

			encrypt(f,dos,encrCipher);

			dos.writeInt(END);
			dos.close();
		} catch (Exception e) {
			throw new CantEncryptException();
		}
		Files.delete(f.toPath());
	}

	public static void encrypt(File f, DataOutputStream dos, Cipher encrCipher) throws IOException, IllegalBlockSizeException, BadPaddingException
	{
		if (f.isDirectory())
		{
			dos.writeInt(DIR);
			byte[] encrName=encrCipher.doFinal(f.getName().getBytes());
			dos.writeInt(encrName.length);
			dos.write(encrName);
			File[] files=f.listFiles();
			int nbFiles=files.length;
			for (int i=0 ; i<nbFiles ; i++)
			{
				File ff = files[i];
				encrypt(ff,dos,encrCipher);
				Files.delete(ff.toPath());
			}
			dos.writeInt(NEXTFILE);
		}
		else
		{
			FileInputStream fis = new FileInputStream(f);

			dos.writeInt(FILE);
			byte[] encrName=encrCipher.doFinal(f.getName().getBytes());
			dos.writeInt(encrName.length);
			dos.write(encrName);

			byte[] data=new byte[PACKET_SIZE];
			while ((fis.read(data))!=-1)
			{
				byte[] encryptedFile = encrCipher.doFinal(data);
				dos.writeInt(encryptedFile.length);
				int sz=encryptedFile.length;
				int packetWritten=0;
				while (sz>0)
				{
					dos.write(encryptedFile,packetWritten*SMALL_PACKET_SIZE,
							sz<SMALL_PACKET_SIZE?sz:SMALL_PACKET_SIZE);
					sz-=SMALL_PACKET_SIZE;
					packetWritten++;
					countToSmallPacketSize++;
					if (countToSmallPacketSize>=SMALL_PACKET_SIZE)
					{
						current++;
						countToSmallPacketSize=0;
					}
				}
			}
			dos.writeInt(NEXTFILE);
			fis.close();
		}
	}

	public static void initDecrypt(File f, String pass) throws CantDecryptException, WrongPasswordException, IOException
	{
		try {
			if (f.isDirectory())
			{
				File[] files=f.listFiles();
				int nbFiles=files.length;
				for (int i=0 ; i<nbFiles ; i++)
				{
					File ff = files[i];
					if (cryptedFiles.contains(ff.getAbsolutePath()))
						initDecrypt(ff, pass);
				}
				return;
			}
			Cipher desCipher=initCipher(Cipher.DECRYPT_MODE, pass);
			FileInputStream fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] tagArray = new byte[TAG.length()];
			dis.readFully(tagArray);
			String fileTag=new String(tagArray);
			if (!fileTag.equals(TAG))
			{
				dis.close();
				throw new CantDecryptException();
			}

			int tipSize = dis.readInt();
			byte[] encrTipArray = new byte[tipSize];
			dis.readFully(encrTipArray);
			MASTERdesCipher.doFinal(encrTipArray);

			int type=0;
			while (type!=END)
			{
				type=dis.readInt();
				decrypt(type, dis, desCipher, f.getParent()+"/");
			}

			dis.close();
		} catch (BadPaddingException e) {
			throw new WrongPasswordException();
		} catch (Exception e) {
			throw new CantDecryptException();
		}
		Files.delete(f.toPath());
	}

	public static void decrypt(int type, DataInputStream dis, Cipher desCipher, String root) throws CantDecryptException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		int nameSz;
		byte[] encrNameArray;
		String name;
		File outFile;
		int cpt=0;

		switch (type)
		{
		case DIR:
			nameSz = dis.readInt();
			encrNameArray = new byte[nameSz];
			dis.readFully(encrNameArray);
			name = new String(desCipher.doFinal(encrNameArray));
			outFile = new File(root+name);
			while (outFile.exists())
				outFile=new File(root+name+" ("+(++cpt)+")");

			outFile.mkdir();
			int nextType=0;
			while ((nextType=dis.readInt())!=NEXTFILE)
				decrypt(nextType,dis,desCipher,root+outFile.getName()+"/");

			break;
		case FILE:
			nameSz = dis.readInt();
			encrNameArray = new byte[nameSz];
			dis.readFully(encrNameArray);
			name = new String(desCipher.doFinal(encrNameArray));
			outFile = new File(root+name);
			if (outFile.exists())
			{
				int indexSep=name.length()-1;
				for (int i=0;i<name.length();i++)
				{
					char c = name.charAt(i);
					if (c=='.')
						indexSep=i;
				}
				String prefix=name.substring(0, indexSep);
				String suffix=name.substring(indexSep,name.length());
				while (outFile.exists())
					outFile=new File(root+prefix+" ("+(++cpt)+") "+suffix);
			}

			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outFile,false));
			int sz;
			byte[] decryptedFile = null;

			while ((sz=dis.readInt())!=NEXTFILE)
			{
				byte[] data = new byte[sz];
				dis.readFully(data);
				decryptedFile = desCipher.doFinal(data);
				int packetWritten=0;
				sz=decryptedFile.length;
				while (sz>0)
				{
					bos.write(decryptedFile,packetWritten*SMALL_PACKET_SIZE,
							sz<SMALL_PACKET_SIZE?sz:SMALL_PACKET_SIZE);
					sz-=SMALL_PACKET_SIZE;
					packetWritten++;
					countToSmallPacketSize++;
					if (countToSmallPacketSize>=SMALL_PACKET_SIZE)
					{
						current++;
						countToSmallPacketSize=0;
					}
				}
			}
			bos.close();
			break;
		case END:
			return;
		default:
			throw new CantDecryptException();
		}
	}

	public static void printAvancement()
	{
		System.out.print("\rAvancement : "+(int)(current*100/totalSize)+"%                       \r");
	}

	private static double totalLength(File f) throws IOException
	{
		int size=0;
		if (!f.isDirectory())
		{
			return Files.size(f.toPath())/SMALL_PACKET_SIZE;
		}
		else
		{
			File[] files=f.listFiles();
			int nbFiles=files.length;
			for (int i=0 ; i<nbFiles ; i++)
			{
				File ff = files[i];
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
				try
				{
					nbFile(args);
				} catch (InterruptedException e)
				{
					e.printStackTrace();
				}
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

	private static void printStart(String[] args)
	{
		System.out.println("*************************************************************");
		if (args.length==2)
		{
			File f = new File(args[1]);
			if (MODE==ENCRYPT_MODE)
				System.out.println("ENCRYPTAGE DU FICHIER : \n     - "+f.getAbsolutePath());
			else
				System.out.println("DECRYPTAGE DU FICHIER : \n     - "+f.getAbsolutePath());
		}
		else
		{
			if (MODE==ENCRYPT_MODE)
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
			switch (args[0])
			{
			case "d":
				MODE=DECRYPT_MODE;
				break;
			case "D":
				MODE=DECRYPT_MODE;
				break;
			case "e":
				MODE=ENCRYPT_MODE;
				break;
			case "E":
				MODE=ENCRYPT_MODE;
				break;
			default:
				System.out.println("Erreur : Argument invalide : le 1er argument doit être E (pour encrypter) ou D (pour décrypter)");
				Thread.sleep(10000);
				System.exit(0);
			}

			MASTERdesCipher=initCipher(Cipher.DECRYPT_MODE, MASTER_KEY);
			MASTERencrCipher=initCipher(Cipher.ENCRYPT_MODE, MASTER_KEY);
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

		printStart(args);



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
		if (MODE==ENCRYPT_MODE) 
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
			if (tip==null || tip.equals(""))
				tip="Aucune aide entrée.";
		}
		else
		{
			initCountFilesThread(args);
			initPrintAnalysesThread();
			running=true;
			countFilesThread.start();
			printAnalysisThread.start();
			Thread.sleep(10);

			generateTipsAndCryptedFilesList(args);
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

		if (MODE==ENCRYPT_MODE) 
			for (int i=1;i<args.length;i++)
				initAction(new File(args[i]));
		else if (MODE==DECRYPT_MODE) 
			for (String fileName : cryptedFiles)
				initAction(new File(fileName));

		Thread.sleep(2000);
	}

	private static void initAction(File f) throws InterruptedException, IOException
	{
		nbFile=0;
		nbFail=0;
		running=true;
		totalSize=totalLength(f);
		current=0;
		countToSmallPacketSize=0;
		initPrintStateThread();
		printStateThread.start();
		Thread.sleep(10);
		boolean success=doAction(f);

		Thread.sleep(10);
		System.out.println((MODE==DECRYPT_MODE?"Décryptage":"Encryptage")+(success?" Réussi : ":" Echoué : ")+ f.getName() +" "+log);
		Thread.sleep(150);
	}

	private static List<String> getTipFromFile(File f)
	{
		List<String> tips=new ArrayList<>();
		String tip=null;
		if (!f.isDirectory())
		{
			currentFileScanned++;
			try
			{
				FileInputStream fis = new FileInputStream(f);
				DataInputStream dis = new DataInputStream(fis);
				byte[] tagArray = new byte[TAG.length()];
				dis.readFully(tagArray);
				if (!new String(tagArray).equals(TAG))
				{
					dis.close();
					throw new Exception();
				}
				int tipSz=dis.readInt();
				byte[] tipArrayEncr=new byte[tipSz];
				dis.readFully(tipArrayEncr);
				byte[] tipArray = MASTERdesCipher.doFinal(tipArrayEncr);
				tip=new String(tipArray);
				fis.close();
				dis.close();
				tips.add(tip);
				cryptedFiles.add(f.getAbsolutePath());
			} catch (OutOfMemoryError | Exception e) {

			}
		}
		else
		{
			File[] files=f.listFiles();
			int nbFiles=files.length;
			for (int i=0 ; i<nbFiles ; i++)
			{
				File ff = files[i];
				for (String str : getTipFromFile(ff))
					tips.add(str);
			}
		}
		return tips;
	}

	private static boolean doAction(File f) throws InterruptedException, IOException
	{
		boolean success=true;
		try
		{
			if (MODE==ENCRYPT_MODE) 
				initEncrypt(f, new File(f.getParent()+"/ENCRYPTED_"+f.getName()), mdp);
			else if (MODE==DECRYPT_MODE) 
				initDecrypt(f,mdp);
		} catch (CantEncryptException e) {
			success=false;
			running=false;
			log=e.getMessage();
		} catch (WrongPasswordException e)
		{
			success=false;
			running=false;
			if (MODE==DECRYPT_MODE)
				success = retryDecrypt(f);
		} catch (CantDecryptException e)
		{
			success=false;
			running=false;
			log="Impossible de décrypter le fichier.";
		} 

		running=false;
		if (success)
			log="";
		Thread.sleep(150);
		return success;
	}

	private static boolean retryDecrypt(File f) throws InterruptedException, IOException
	{
		List<String> tips=getTipFromFile(f);

		log="Mot de passe invalide.";
		if (!nToAll)
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
				return doAction(f);
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

	private static void generateTipsAndCryptedFilesList(String[] args) throws InterruptedException
	{
		ExecutorService es = Executors.newCachedThreadPool();
		for (int i=1;i<args.length;i++)
		{
			final int index = i;
			es.submit(new Runnable()
			{
				@Override
				public void run()
				{
					File f=new File(args[index]);
					List<String> fileTips = getTipFromFile(f);
					for (String fileTip : fileTips)
						if (!tips.contains(fileTip))
							tips.add(fileTip);
				}
			});
		}
		es.shutdown();
		es.awaitTermination(60, TimeUnit.MINUTES);
	}

	private static void nbFile(File f)
	{
		if (!f.isDirectory())
		{
			totalFilesToScan++;
			return;
		}
		File[] files=f.listFiles();
		int nbFiles=files.length;
		for (int i=0 ; i<nbFiles ; i++)
		{
			File ff = files[i];
			nbFile(ff);
		}
	}

	private static void nbFile(String[] args) throws InterruptedException
	{
		ExecutorService es = Executors.newCachedThreadPool();
		for (int i=1;i<args.length;i++)
		{
			final int index = i;
			es.submit(new Runnable()
			{
				@Override
				public void run()
				{
					nbFile(new File(args[index]));
				}
			});
		}
		es.shutdown();
		es.awaitTermination(60, TimeUnit.MINUTES);
	}
}