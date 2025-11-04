#region Packing
public class ZeroesPaddingMode : IPaddingMode
{
    public byte[] packMissingBytes(in byte[] bytes, int neededLength)
    {
        if (bytes.Length != neededLength)
        {
            byte[] result = new byte[neededLength];
            Array.Copy(bytes, result, bytes.Length);
            Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length);
            return result;
        }
        return (byte[])bytes.Clone();
    }

    public byte[] unpackMissingBytes(in byte[] bytes)
    {
        int lastNonZeroIndex = bytes.Length - 1;
        while (lastNonZeroIndex >= 0 && bytes[lastNonZeroIndex] == 0)
        {
            lastNonZeroIndex--;
        }

        if (lastNonZeroIndex < 0)
        {
            return new byte[0];
        }

        byte[] result = new byte[lastNonZeroIndex + 1];
        Array.Copy(bytes, result, lastNonZeroIndex + 1);
        return result;
    }
}

public class ANSI_X923PaddingMode : IPaddingMode
{
    public byte[] packMissingBytes(in byte[] bytes, int neededLength)
    {
        if (bytes.Length != neededLength)
        {
            byte[] result = new byte[neededLength];
            Array.Copy(bytes, result, bytes.Length);

            Array.Fill<byte>(result, 0, bytes.Length, neededLength - bytes.Length - 1);
            result[result.Length - 1] = (byte)(neededLength - bytes.Length);
            return result;
        }
        return (byte[])bytes.Clone();
    }

    public byte[] unpackMissingBytes(in byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return (byte[])bytes.Clone();
        }

        byte paddingLength = bytes[bytes.Length - 1];

        if (paddingLength == 0 || paddingLength > bytes.Length)
        {
            return (byte[])bytes.Clone();
        }

        for (int i = bytes.Length - paddingLength; i < bytes.Length - 1; i++)
        {
            if (bytes[i] != 0)
            {
                return (byte[])bytes.Clone();
            }
        }

        byte[] result = new byte[bytes.Length - paddingLength];
        Array.Copy(bytes, result, bytes.Length - paddingLength);
        return result;
    }
}

public class PKCS7PaddingMode : IPaddingMode
{
    public byte[] packMissingBytes(in byte[] bytes, int neededLength)
    {
        if (bytes.Length != neededLength)
        {
            byte[] result = new byte[neededLength];
            Array.Copy(bytes, result, bytes.Length);

            Array.Fill<byte>(
                result,
                (byte)(neededLength - bytes.Length),
                bytes.Length,
                neededLength - bytes.Length
            );
            return result;
        }
        return (byte[])bytes.Clone();
    }

    public byte[] unpackMissingBytes(in byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return (byte[])bytes.Clone();
        }

        byte paddingLength = bytes[bytes.Length - 1];

        if (paddingLength == 0 || paddingLength > bytes.Length)
        {
            return (byte[])bytes.Clone();
        }

        for (int i = bytes.Length - paddingLength; i < bytes.Length; i++)
        {
            if (bytes[i] != paddingLength)
            {
                return (byte[])bytes.Clone();
            }
        }

        byte[] result = new byte[bytes.Length - paddingLength];
        Array.Copy(bytes, result, bytes.Length - paddingLength);
        return result;
    }
}

public class ISO10126PaddingMode : IPaddingMode
{
    public byte[] packMissingBytes(in byte[] bytes, int neededLength)
    {
        if (bytes.Length != neededLength)
        {
            byte[] result = new byte[neededLength];
            Array.Copy(bytes, result, bytes.Length);

            Random rand = new Random();
            for (int i = bytes.Length; i < neededLength - 1; i++)
            {
                result[i] = (byte)rand.Next(0, 256);
            }
            result[result.Length - 1] = (byte)(neededLength - bytes.Length);
            return result;
        }
        return (byte[])bytes.Clone();
    }

    public byte[] unpackMissingBytes(in byte[] bytes)
    {
        if (bytes.Length == 0)
            return (byte[])bytes.Clone();

        byte paddingLength = bytes[bytes.Length - 1];

        if (paddingLength == 0 || paddingLength > bytes.Length)
        {
            return (byte[])bytes.Clone();
        }

        byte[] result = new byte[bytes.Length - paddingLength];
        Array.Copy(bytes, result, bytes.Length - paddingLength);
        return result;
    }
}

public enum PaddingMode : byte
{
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO10126,
}

#endregion
