# CLI Contracts

Command Line Interface for Contracts.

**The idea**:

By implementing a CLI version of a contract, we provide an interface to
manipulate contracts directly from the shell. Each clicontract should stay in
its own file accompagned by its test file.

To make things simpler to use, implement, and maintain, we use the same set of
commands and functionalities among clicontracts.

**Commands convention**:

```bash
$ bcadmin contract <contract name> {spawn,invoke <command>, delete, get}\
                                   [--<param name> <param value>, ...]\
                                   [--sign <signer id>] [--darc <darc id>]\
                                   [--redirect]
```

**Functionalities**:

* With the `--redirect`, the contract's transaction should not be executed, but
redirected to stdout.

* Each contract should have a `get` function, which allows one to get the
contract's data given its instance id with `--instID`.

**Global conventions**:

* *inst* stands for *instance*
* *instr* stands for *instruction*
* *id* stands for *identifier*
* *idx* stands for *index*

**Command examples**:

Spawn a value contract:

```bash
$ bcadmin contract value spawn --value "Hello World"
```

Update a value contract:

```bash
# The --instID is given when we spawn the value contract
$ bcadmin contract value invoke update --value "Bye World" --instID ...
```

Spawn a deferred contract with a value contract as the proposed transaction:

```bash
$ bcadmin contract value spawn --value "Hello Word" --redirect | bcadmin contract deferred spawn
```

Invoke an addProof on a deferred contract:

```bash
# The --hash and --instID values are given when we spawn the deferred contract
bcadmin contract deferred invoke addProof --hash ... --instID ... --iid 0
```

**Working scenario**:

```bash
# Run the nodes, create roster and set up the config
~/GitHub/cothority/conode/run_nodes.sh -n 5 -c -t -v 2
bcadmin create -roster ~/GitHub/cothority/conode/public.toml 

# Copy/Paste from the output of the previous command
export BC="..."

# Add the rules specific to the value and deferred contracts.
# We use the admin identity.
bcadmin darc rule -rule spawn:value --identity ed25519:... 
bcadmin darc rule -rule spawn:deferred --identity ed25519:...                                                         
bcadmin darc rule -rule invoke:deferred.addProof --identity ed25519:...        
bcadmin darc rule -rule invoke:deferred.execProposedTx --identity ed25519:...                                                                                                                                                     

# Spawn a value contract, but redirect the transaction to the spawn of a deferred contract
bcadmin contract value spawn --value myValue --redirect | bcadmin contract deferred spawn

# Add the proof on the single instruction of the deferred transaction 
# (the --hash and --instID values are given when we spawn the deferred contract)
bcadmin contract deferred invoke addProof --hash ... --instID ... --iid 0

# Finally execute the deferred transaction.
# This will call the Spawn:value(myValue) transaction.
# If we hadn't called the addProof before, it wouldn't have worked.
bcadmin contract deferred invoke execProposedTx --instID ...
```