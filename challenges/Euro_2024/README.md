# Euro_2024
*It is a widely known fact that elia is a diehard fan of football. For this reason he built a website to display the group stats of the EURO 2024 tournament but it seems like he left a secret somewhere.*
`https://euro2024.challs.pascalctf.it/`

## Solution
1. So, we're given a website and the source-code to this webapp. A quick `snyk code test` tells us that there is a possible SQLi vulnerabillity here. After some looking around I could confirm that it indeed looks like a possible SQLi!
2. So, first off, I'm gonna fire up a local version to test against, then we'll have to start poking around in the injectable parameter.
3. For some example `sqlmap` refused to access the local instance, so i went straight for the public instead... `sqlmap -u 'https://euro2024.challs.pascalctf.it/api/group-stats' --data 'group=*' --all` will dump the whole DB and get you the flag.


## Flag
**Flag:** `pascalCTF{fl4g_is_in_7h3_eyes_of_the_beh0lder}`
