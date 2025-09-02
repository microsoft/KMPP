#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Get the OpenSSL config directory
config_dir=$(openssl info -configdir 2>/dev/null)
echo "Config dir $config_dir"

# Define the path to the openssl.cnf file
config_file="$config_dir/openssl.cnf"
backup_file="$config_file.bak"

# Check if the config file exists
if [ ! -f "$config_file" ]; then
    echo "OpenSSL config file not found at $config_file"
    exit 1
fi

# Check if the backup config file exists
if [ ! -f "$backup_file" ]; then
    echo "Backup OpenSSL config file not found at $backup_file"
    exit 1
fi

# check if the line "openssl_conf = openssl_init" exists in current config
openssl_conf_line=$(grep -n "^\s*openssl_conf\s*=\s*openssl_init" "$config_file" | cut -d: -f1)
if [ -n "$openssl_conf_line" ]; then
    # Get the backup format of the line (commented or uncommented)
    backup_line=$(grep -n "^\s*#*\s*openssl_conf\s*=\s*openssl_init" "$backup_file" | cut -d: -f1)
    if [ -n "$backup_line" ]; then
        # Get the exact format from backup
        backup_format=$(grep "^\s*#*\s*openssl_conf\s*=\s*openssl_init" "$backup_file")
        # Replace current line with backup format
        sed -i "${openssl_conf_line}c\\${backup_format}" "$config_file"
        echo "Restored openssl_conf line format from backup"
    fi
fi


# If didnt exist remove "providers = provider_sect" line
provider_init_line="providers = provider_sect"
# Check if the line exists in the config file
if grep -q "^$provider_init_line" "$config_file"; then
    # If the line does not exist in the backup, remove it from the current config file
    if ! grep -q "^$provider_init_line" "$backup_file"; then
        sed -i "/^$provider_init_line/d" "$config_file"
    # If the line is commented in the backup file, comment it in the current config file
    elif grep -q "^#$provider_init_line" "$backup_file"; then
        sed -i "s/^$provider_init_line/#$provider_init_line/" "$config_file"
    fi
fi

# Remove the include lines for KMPP
sed -i '/\.include.*kmpp_dflt_prov\.cnf/d' "$config_file"

# Check if the SymCrypt include line exists before removing it
if grep -q "\.include.*symcrypt_prov\.cnf" "$config_file"; then
    sed -i '/\.include.*symcrypt_prov\.cnf/d' "$config_file"
fi

# Remove the provider entries for KMPP
sed -i '/kmppprovider_dflt = kmppprovider_dflt_sect/d' "$config_file"

# Check if the SymCrypt provider entry exists before removing it
if grep -q "symcryptprovider = symcrypt_prov_sect" "$config_file"; then
    sed -i '/symcryptprovider = symcrypt_prov_sect/d' "$config_file"
fi

# Check if the "default = default_sect" entry exists and if it didn't exist in the backup file, remove it
if grep -q "default = default_sect" "$config_file" && ! grep -q "default = default_sect" "$backup_file"; then
    sed -i '/default = default_sect/d' "$config_file"
fi

# Check if the [provider_sect] section title exists and if it didn't exist in the backup file, remove it
if grep -q "\[provider_sect\]" "$config_file" && ! grep -q "\[provider_sect\]" "$backup_file"; then
    sed -i '/\[provider_sect\]/d' "$config_file"
fi

# Restore the evp_settings section from the backup file if KMPP is configured
if grep -q "default_properties.*provider=kmppprovider_dflt" "$config_file"; then
    # Check if the evp_settings section exists in the backup file
    if grep -q "\[evp_settings\]" "$backup_file"; then
        # Extract the default_properties line from the backup file
        default_properties_backup=$(awk '/\[evp_settings\]/ {getline; print}' "$backup_file")
        echo "default_properties_backup: $default_properties_backup"
        # Update the default_properties line in the current evp_settings section
        sed -i "/\[evp_settings\]/,/^\[/ s/default_properties.*/$default_properties_backup/" "$config_file"
        
        # Update the comment above [evp_settings] if it exists in the backup file, otherwise remove it
        if grep -q "# Use the SymCrypt provider by default, if available" "$backup_file"; then
            evp_settings_comment=$(grep "# Use the SymCrypt provider by default, if available" "$backup_file")
            sed -i "s/# Use the KMPP provider by default, if available/$evp_settings_comment/" "$config_file"
        else
            sed -i '/# Use the KMPP provider by default, if available/d' "$config_file"
        fi
    else
        # Remove the current evp_settings section if it was added by the installation script
        echo "Removing [evp_settings] section"
        sed -i '/# Use the KMPP provider by default, if available/d' "$config_file"
        sed -i '/\[evp_settings\]/,/default_properties = "?provider=kmppprovider_dflt"/d' "$config_file"

    fi
fi

# Remove the [default_sect] section if it was added by the installation script
section_str="[default_sect]"
activate_str="activate = 1"

config_sect_line=$(grep -n "^\s*\[default_sect\]" "$config_file" | cut -d: -f1)

if grep -q "^$section_str" "$config_file"; then
    if ! grep -q "^$section_str" "$backup_file"; then
        # Not found in backup, remove [default_sect] and activate = 1
        echo "*** default section didn't exist"
        sed -i "${config_sect_line}d;${config_sect_line}d" "$config_file"
    elif grep -q "^\s*#\s*\[default_sect\]" "$backup_file"; then
        echo "*** default section was commented"
        # Comment both [default_sect] and activate = 1 robustly
        sed -i "${config_sect_line}s/^[[:space:]]*/# /" "$config_file" 
        sed -i "$((config_sect_line + 1))s/^[[:space:]]*/# /" "$config_file"
    # if the default_sect is not cxommented but the activate is
    elif grep -Pzq "\[default_sect\]\s*\n\s*#\s*activate" "$backup_file"; then
        echo "*** activated section was commented"
        # Comment and activate = 1 robustly
        sed -i "$((config_sect_line + 1))s/^[[:space:]]*/# /" "$config_file"
    fi
fi


echo "Reverted changes in $config_file"