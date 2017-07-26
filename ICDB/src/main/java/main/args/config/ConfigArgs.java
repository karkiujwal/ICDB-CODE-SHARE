package main.args.config;

import crypto.AlgorithmType;
import main.args.option.Granularity;

/**
 * Represents a configuration file
 * All the information included in config.json file is used in this class attributes.
 *
 */
public class ConfigArgs {
    public String ip;
    public int port;
    public String user;
    public String password;
    public String schema;
    public String icdbSchema;
    public Granularity granularity;
    public AlgorithmType algorithm;
    public String macKey;
    public String rsaKeyFile;
    public boolean validateIcrl;
}
