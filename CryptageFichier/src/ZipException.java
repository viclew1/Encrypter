
public class ZipException extends Exception
{
	public ZipException()
	{
		super("Impossible d'encrypter un zip, jar ou 7z pour l'instant.");
	}
}
