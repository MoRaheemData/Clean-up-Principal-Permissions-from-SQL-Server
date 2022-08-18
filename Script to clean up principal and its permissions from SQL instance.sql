/*
	Script to clean up principal and its permissions from SQL instance

	Notes:
		- Does not include permissions that the principal inherits eg. AD Groups, public
		- This script ONLY generates the stmts for you to run, it doesn't execute anything itself
		- The following is checked and printed:
			- Transfer of owned objects to [dbo] to avoid errors. Principals which own objects can't be dropped. 
			- Revoke database level permissions 
			- Remove database role mappings 
			- Drop database user 
			- Revoke instance level perms 
			- Drop sql login 

	Instructions:
		- Pre-req: "Record Permissions" security audit process must be set up on the SQL instance
			- didn't want to re-add all of the logic of gathering perms to this script
		- Run query window in "Results to Text" mode (CTRL + T)
		- Set @PrincipalName variable for the principal in question

	Author		Date		Notes
	Mo Raheem	20220817	Created
*/
set nocount on;

declare 
	@PrincipalName varchar(128) = 'MY DOMAIN\username', /*** TO BE SET BY USER ***/
	@sid varbinary(85),
	@ServerName varchar(257) = (select @@servername),
	@DBName varchar(128),
	@SchemaName varchar(128),
	@SQLStmt varchar(4000)
;

if not exists (select 1 from master.sys.syslogins where [name] = @PrincipalName)
begin
	raiserror('This principal does not exist on the instance: %s. This user may have access through other membership. Run a comprehensive permissions assessment like: https://raw.githubusercontent.com/MoRaheemData/Mo_Raheem_SQL_Server_Security_Assessment/main/Mo_Raheem_Security_Assessment.sql'
		,1,1, @ServerName) with nowait;
end
else
begin

/* query sid of @PrincipalName for more accurate results
	eg. principal vs db user name mismatches */
set @sid = (select [sid] from master.sys.syslogins where [name] = @PrincipalName);


/* 
	Transfer of owned objects to [dbo] 
*/
drop table if exists #DBName;
create table #DBName (
	DBName varchar(128),
	IsProcessed bit default 0
);
/* gather db names which user has access to */
insert #DBName (DBName)
select 
	distinct [Scope]
from
	[DbaToolbox].[security_audit].[DatabaseObjectLevel]
where
	[sid] = @sid;

while exists (select 1 from #DBName where IsProcessed = 0)
begin
	select top 1 
		@DBName = DBName 
	from 
		#DBName 
	where 
		IsProcessed = 0;

	drop table if exists #OwnedSchemaName;
	create table #OwnedSchemaName (
		SchemaName varchar(128),
		IsProcessed bit default 0
	);

	/* identify owned schemas */
	set @SQLStmt = 
	'insert #OwnedSchemaName (SchemaName)
	select	
		s.name
	from 
		[' + @DBName + '].sys.schemas s
		inner join [' + @DBName + '].sys.database_principals d
			on d.principal_id = s.principal_id
	where
		d.name = ( select name from [' + @DBName + '].sys.database_principals where [sid] = ''' +  CONVERT(VARCHAR(1000),@sid,2) + ''');';
	exec(@SQLStmt);

	while exists (select 1 from #OwnedSchemaName where IsProcessed = 0)
	begin
		select top 1
			@SchemaName = SchemaName
		from
			#OwnedSchemaName 
		where 
			IsProcessed = 0;

		print 'use [' + @DBName + '];'
		print 'go'
		print 'alter authorization on schema::[' + @SchemaName + '] to [dbo];'
		print 'go'
	
		update #OwnedSchemaName
		set
			IsProcessed = 1
		where
			SchemaName = @SchemaName;
	end

	update #DBName
	set
		IsProcessed = 1
	where
		DBName = @DBName;
end


/* 
	Revoke database level permissions 
*/
select 
	case  
		when [SchemaName] != 'N/A' then 'use [' + Scope + '];' +char(10)+ 'go' +char(10)+ 'revoke ' + [PermissionType] + ' on [' + [SchemaName] + '] to [' + [PrincipalName] + '] as [dbo];' +char(10)+ 'go' +char(10)
		else 'use [' + Scope + '];' +char(10)+ 'go' +char(10)+ 'revoke ' + [PermissionType] + ' to [' + [PrincipalName] + '];' +char(10)+ 'go' +char(10)
	end 
from 
	[DbaToolbox].[security_audit].[DatabaseObjectLevel]
where
	[sid] = @sid
	and [PermissionType] != 'CONNECT'; /* no need to deny connect - do so by running drop user stmts */


/* 
	Remove database role mappings 
*/
select 
	'use [' + [Scope] + '];' +char(10)+
	'go' +char(10)+
	'alter role [' + [DatabaseRole] + '] drop member [' + [PrincipalName] + '];' +char(10)+
	'go' +char(10)
from 
	[DbaToolbox].[security_audit].[PrincipalToDatabaseRoleMappings]
where 
	[sid] = @sid;


/* 
	Drop database user 
*/
select 
	distinct 'use [' + [Scope] + '];' +char(10)+
	'go' +char(10)+
	'drop user [' + PrincipalName + '];' +char(10)+
	'go' +char(10)
from 
	[DbaToolbox].[security_audit].[DatabaseObjectLevel]
where
	[sid] = @sid;


/* 
	Revoke instance level perms 
*/
select 
	case 
		when [EndpointName] = 'N/A' then 'use [master];' +char(10)+ 'go' +char(10)+ 'revoke ' + [PermissionType] + ' to [' + [PrincipalName] + '] as [sa];' +char(10)+ 'go'
		else 'use [master];' +char(10)+ 'go' +char(10)+ 'alter server role [' + [EndpointName] + '] drop member [' + [PrincipalName] + '];' +char(10)+ 'go'
	end
from 
	[DbaToolbox].[security_audit].[InstanceLevel]
where 
	[sid] = @sid;

/* 
	Drop sql login 
*/
select
	distinct 'use [master];' +char(10)+
	'go' +char(10)+
	'drop login [' + [PrincipalName] + '];' +char(10)+
	'go' +char(10)
from 
	[DbaToolbox].[security_audit].[InstanceLevel]
where 
	[sid] = @sid;

end