# Path to the CSV file containing the list of usernames, first names, and last names
$csvPath = "C:\Path\To\Your\Users.csv"  

# Import the list of users from the CSV
$userList = Import-Csv -Path $csvPath

# Loop through each user in the CSV
foreach ($user in $userList) {
    $username = $user.Username
    $firstName = $user.FirstName
    $lastName = $user.LastName

    Write-Host "Creating mailbox for user $username..."

    # Create the mailbox for the user with FirstName and LastName
    New-Mailbox -UserPrincipalName "$username@domain.com" `
                -Alias $username `
                -Name "$firstName $lastName" `
                -FirstName $firstName `
                -LastName $lastName `
                -DisplayName "$firstName $lastName" `
                -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
    
    Write-Host "Mailbox created for user $username"
}
