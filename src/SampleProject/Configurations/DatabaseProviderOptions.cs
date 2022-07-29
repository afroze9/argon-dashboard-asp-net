namespace SampleProject.Configurations;

public class DatabaseProviderOptions
{
    public const string MSSQL = "MSSQL";
    public const string PostgreSQL = "PostgreSQL";
    public const string MySQL = "MySQL";
    public const string Sqlite = "Sqlite";

    public const string MSSQLConnectionStringName = "MSSQLConnection";
    public const string PostgreSQLConnectionStringName = "PostgreSQLConnection";
    public const string MySQLConnectionStringName = "MySQLConnection";
    public const string SqliteConnectionStringName = "SqliteConnection";

    public string Provider { get; set; }
}