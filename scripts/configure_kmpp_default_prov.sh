#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Get the OpenSSL config directory
config_dir=$(openssl info -configdir 2>/dev/null)
echo "Config dir $config_dir"

# Define the path to the openssl.cnf file
config_file="$config_dir/openssl.cnf"

# Check if the config file exists
if [ ! -f "$config_file" ]; then
    echo "OpenSSL config file not found at $config_file"
    exit 1
fi

# Backup the original config file
cp "$config_file" "$config_file.bak"
# Set permission to file
chmod 644 "$config_file.bak"
chown root:root "$config_file.bak"

echo "Created backup of OpenSSL config at $config_file.bak"

# Define evp_settings content
evp_settings_section="# Use the KMPP provider by default, if available\n[evp_settings]\ndefault_properties = \"?provider=kmppprovider_dflt\""

#################################
## Handle openssl_init section ##
#################################
# Find [openssl_init] section and its line number if it exists
openssl_init_exists=false
openssl_init_line=0
evp_settings_exists=false
symcrypt_is_default=false

# check if the line "openssl_conf = openssl_init" exists (uncommented)
openssl_conf_line=$(grep -n "^\s*openssl_conf\s*=\s*openssl_init" "$config_file" | cut -d: -f1)
if [ -n "$openssl_conf_line" ]; then
    echo "Found uncommented openssl_conf line"
else
    # Check if the line exists but is commented out (handle both comment formats)
    commented_openssl_conf_line=$(grep -n "^\s*#\s*openssl_conf\s*=\s*openssl_init" "$config_file" | cut -d: -f1)
    if [ -n "$commented_openssl_conf_line" ]; then
        echo "Found commented openssl_conf line with no space after #, uncommenting"
        sed -i "${commented_openssl_conf_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
    else
        # Check for comments that have space(s) after the # symbol
        commented_openssl_conf_line=$(grep -n "^\s*#[[:space:]]\+openssl_conf\s*=\s*openssl_init" "$config_file" | cut -d: -f1)
        if [ -n "$commented_openssl_conf_line" ]; then
            echo "Found commented openssl_conf line with space after #, uncommenting"
            sed -i "${commented_openssl_conf_line}s/^[[:space:]]*#[[:space:]]\+//" "$config_file"
        else
            # Add the line if it doesn't exist at all
            echo "Adding openssl_conf line"
            echo "openssl_conf = openssl_init" >> "$config_file"
        fi
    fi
fi


if grep -q "\[openssl_init\]" "$config_file"; then
    openssl_init_exists=true
    openssl_init_line=$(awk '/\[openssl_init\]/ && !/^#/{print NR; exit}' "$config_file")
fi

# Check if [evp_settings] exists and if SymCrypt is the default provider
if grep -q "\[evp_settings\]" "$config_file"; then
    evp_settings_exists=true

    # Check if the [evp_settings] section header is commented
    commented_evp_sect_line=$(grep -n "^\s*#\s*\[evp_settings\]" "$config_file" | cut -d: -f1)
    if [ -n "$commented_evp_sect_line" ]; then
        echo "Found commented [evp_settings] section, uncommenting"
        sed -i "${commented_evp_sect_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
    fi

    # Check if SymCrypt is the default provider
    if grep -q "default_properties.*provider=symcryptprovider" "$config_file"; then
        symcrypt_is_default=true
        echo "SymCrypt is configured as the default provider."

        # check if the line is commented out in if so uncomment it
        commented_symcrypt_line=$(grep -n "^\s*#\s*default_properties.*provider=symcryptprovider" "$config_file" | cut -d: -f1)
        if [ -n "$commented_symcrypt_line" ]; then
            echo "Found commented default_properties line for SymCrypt, uncommenting"
            sed -i "${commented_symcrypt_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
        fi   
    else
        echo "SymCrypt is not configured as the default provider."
    fi
fi

# Find the line after openssl_init where the next section starts (if openssl_init exists)
next_section_after_init=0
if $openssl_init_exists; then
    next_section_line=$(tail -n +$((openssl_init_line+1)) "$config_file" | grep -n "^\[" | head -1)

    if [ -n "$next_section_line" ]; then
        line_num=$(echo "$next_section_line" | cut -d: -f1)
        next_section_after_init=$((openssl_init_line + line_num - 2))
    fi
fi

# Define the individual include directives
include_line_symcrypt=".include = $config_dir/symcrypt_prov.cnf   # Include external configuration file"
include_line_kmpp=".include = $config_dir/kmpp_dflt_prov.cnf       # Include external configuration file"
provider_init="providers = provider_sect"

# Prepare include lines to add - always include KMPP
includes_to_add="$include_line_kmpp"

# First handle the openssl_init section since we need it for ordering
if $openssl_init_exists; then

    # Check if "providers = provider_sect" line exists
    providers_line_exists=$(grep -q "$provider_init" "$config_file" && echo true || echo false)
    if $providers_line_exists; then
        # Check if the providers line is commented
        commented_providers_line=$(grep -n "^\s*#\s*providers\s*=\s*provider_sect" "$config_file" | cut -d: -f1) 
        if [ -n "$commented_providers_line" ]; then
            sed -i "${commented_providers_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
        fi
    else
        includes_to_add="$includes_to_add\n$provider_init"
    fi

    # Add includes if not already present
    kmpp_needed=false

    # Always need to check if KMPP is already included
    if ! grep -q "\.include.*kmpp_prov\.cnf" "$config_file"; then
        kmpp_needed=true
    fi

    # Only check for SymCrypt include if we're planning to add it
    if $symcrypt_is_default && ! grep -q "\.include.*symcrypt_prov\.cnf" "$config_file"; then
        includes_to_add="$include_line_symcrypt\n$includes_to_add"
        echo "SymCrypt is the default provider, including its config."
    fi

    if $kmpp_needed; then
        if [ $next_section_after_init -gt 0 ]; then
            # Insert includes just before the next section
            insert_line=$next_section_after_init
            sed -i "${insert_line}i\\${includes_to_add}" "$config_file"
            next_section_after_init=$((next_section_after_init + $(echo -e "$includes_to_add" | wc -l)))
        else
            # No next section, append to the file
            sed -i "\$a\\${includes_to_add}" "$config_file"
        fi
    else
        echo "Required provider includes already present, skipping include directives"
    fi
else
    # [openssl_init] doesn't exist, create it with our includes and provider section
    echo -e "\n[openssl_init]\n${includes_to_add}\n${provider_init}" >> "$config_file"
fi

#################################
## Handle evp_settings section ##
#################################
if $evp_settings_exists; then
    # Update comment and default_properties
    sed -i '/# Use the SymCrypt provider by default/{
        s/# Use the SymCrypt provider by default.*/# Use the KMPP provider by default, if available/
    }' "$config_file"

    # Update default_properties to use KMPP provider while preserving other settings
    sed -i '/\[evp_settings\]/,/^\[/ {
        s/default_properties = "?provider=symcryptprovider\([^"]*\)"/default_properties = "?provider=kmppprovider_dflt\1"/
    }' "$config_file"
else
    # Add evp_settings after openssl_init section
    # We can be sure openssl_init exists because we create it if it doesn't
    if [ $next_section_after_init -gt 0 ]; then
        # Insert evp_settings before the next section with a blank line
        sed -i "${next_section_after_init}i\\\n${evp_settings_section}" "$config_file"
    else
        # No next section, add at the end with proper newlines
        echo -e "\n${evp_settings_section}" >> "$config_file"
    fi
fi

##################################
## Handle provider_sect section ##
##################################
provider_sect_exists=$(grep -q "\[provider_sect\]" "$config_file" && echo true || echo false)
next_section_after_evp_settings=0

# Prepare provider entries that need to be added
provider_entries="kmppprovider_dflt = kmppprovider_dflt_sect"

if $symcrypt_is_default; then
    provider_entries="$provider_entries\nsymcryptprovider = symcrypt_prov_sect"
fi

# Add default entry if needed
if ! $provider_sect_exists || ! grep -q "default = default_sect" "$config_file"; then
    provider_entries="$provider_entries\ndefault = default_sect"
fi

# Add section header if creating new section
if ! $provider_sect_exists; then
    provider_entries="[provider_sect]\n$provider_entries"
fi

provider_sect_line=0
# Get Provider section line
if $provider_sect_exists; then
    echo "Updating provider_sect section"

    # Check if the [provider_sect] section header is commented
    commented_provider_sect_line=$(grep -n "^\s*#\s*\[provider_sect\]" "$config_file" | cut -d: -f1)
    if [ -n "$commented_provider_sect_line" ]; then
        echo "Found commented [provider_sect] section, uncommenting"
        sed -i "${commented_provider_sect_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
    fi

    # Get the line number of the first occurrence of [provider_sect] that is not part of a comment
    provider_sect_line=$(awk '/\[provider_sect\]/ && !/^#/{print NR; exit}' "$config_file")
else
    echo "Creating provider_sect section"
    # Find position after evp_settings
    evp_settings_line=$(grep -n "\[evp_settings\]" "$config_file" | cut -d: -f1)
    next_section_line=$(tail -n +$((evp_settings_line+1)) "$config_file" | grep -n "^\[" | head -1)
    if [ -n "$next_section_line" ]; then
        line_num=$(echo "$next_section_line" | cut -d: -f1)
        provider_sect_line=$((evp_settings_line + line_num - 1))
    fi
fi

# Insert the entries at the appropriate position
if [ $provider_sect_line -gt 0 ]; then
    # If we're creating a new section, add a blank line before it
    if ! $provider_sect_exists; then
        sed -i "${provider_sect_line}i\\\n${provider_entries}" "$config_file"
    else
        # Just adding entries to existing section - no blank line needed
        sed -i "${provider_sect_line}a\\${provider_entries}" "$config_file"
    fi
else
    # No suitable insertion point found, append to the file
    echo -e "\n${provider_entries}" >> "$config_file"
fi

##################################
## Handle default_sect section ##
##################################

# Check if default_sect exists and activate = 1.
section_str="[default_sect]"
activate_str="activate = 1"

# Check if default_sect section exists
default_sect_exists=$(grep -q "\[default_sect\]" "$config_file" && echo true || echo false)

if $default_sect_exists; then
    
    # Check if the section header is commented
    commented_default_sect_line=$(grep -n "^\s*#\s*\[default_sect\]" "$config_file" | cut -d: -f1)
    if [ -n "$commented_default_sect_line" ]; then
        echo "Found commented [default_sect] section, uncommenting"
        sed -i "${commented_default_sect_line}s/^[[:space:]]*#[[:space:]]*//" "$config_file"
    fi

    # Check if an uncommented activate = 1 line exists in the correct format
    correct_activate_exists=$(awk "/\\$section_str/{section=1; next} /^\\[/{section=0} section && /^$activate_str\$/{print; exit}" "$config_file")
    
    if [ -n "$correct_activate_exists" ]; then
        echo "Activation already set correctly"
    else
        # Check for any activate line to modify (commented or uncommented) 
        # but only *directly* within the default_sect section (not in commented sections)
        activate_line=$(awk "/\\$section_str/{section=1; next} /^\\[/{section=0} section && /^[[:space:]]*#?[[:space:]]*activate[[:space:]]*=/{print NR; exit}" "$config_file") 
        if [ -n "$activate_line" ]; then
            # Modify the existing activate line
            sed -i "${activate_line}s/^.*$/$activate_str/" "$config_file"
            echo "Modified existing activate line"
        else
            # No activate line found, add it right after the section header
            sed -i "/\\$section_str/a\\$activate_str" "$config_file"
            echo "Added new activate line"   
        fi
    fi
else
    echo "Creating [default_sect] section"
    # Find position of [provider_sect]
    provider_sect_line=$(grep -n "\[provider_sect\]" "$config_file" | cut -d: -f1)
    
    # Find first empty line after [provider_sect]
    empty_line_after_provider=$(tail -n +"$((provider_sect_line + 1))" "$config_file" | grep -n -m 1 '^[[:space:]]*$')    
    if [ -n "$empty_line_after_provider" ]; then
        empty_line_rel=$(echo "$empty_line_after_provider" | cut -d: -f1)
        insert_line=$((provider_sect_line + empty_line_rel))
    else
        # No empty line found, just after [provider_sect]
        insert_line=$((provider_sect_line + 1))
    fi    

    # Insert new section
    new_section="\n$section_str\n$activate_str"
    sed -i "${insert_line}i\\${new_section}" "$config_file"
fi


echo "OpenSSL configuration file has been updated at $config_file"