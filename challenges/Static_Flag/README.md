# Static_Flag
*A friend of mine created a nice frontend, he said we didn't need a backend to check the flag...*

## Solution
1. Too easy...
2. `curl -s https://staticflag.challs.pascalctf.it/ | rg atob | cut -d"'" -f2 | base64 -d`


## Flag
**Flag:** `pascalCTF{S0_y0u_c4n_US3_1nspect_3l3m3nt_t0_ch34t_huh?}`
