#Store the data from ADUsers.csv in the $ADUsers variable
$Users = Import-csv C:\Users\Administrator\Desktop\users.csv

#Loop through each row containing user details in the CSV file 
foreach ($User in $Users) {

    # Read user data from each field in each row
    # the username is used more often, so to prevent typing, save that in a variable

        # create a hashtable for splatting the parameters
        
        $userProps = @{
            SamAccountName        = $User.username.Trim('"') 
            GivenName             = $User.first.Trim('"') 
            Surname               = $User.last.Trim('"') 
            Title                 = $User.title.Trim('"') 
	        Name                  = "$($User.first) $($User.last)"
            AccountPassword       = (ConvertTo-SecureString "$($User.password.Trim('"'))"  -AsPlainText -Force) 
            Enabled               = $true
            ChangePasswordAtLogon = $false
        }   #end userprops   

         New-ADUser @userProps
       
    } #end else
