package com.cloud.upgrade.dao;

import java.io.File;
import java.sql.Connection;

import com.cloud.utils.exception.CloudRuntimeException;
import com.cloud.utils.script.Script;

public class Upgrade430to440 implements DbUpgrade {

    @Override
    public String[] getUpgradableVersionRange() {

        return new String[] {"4.3.0", "4.4.0"};
    }

    @Override
    public String getUpgradedVersion() {
        // TODO Auto-generated method stub
        return "4.4.0";
    }

    @Override
    public boolean supportsRollingUpgrade() {

        return false;
    }

    @Override
    public File[] getPrepareScripts() {
        String script = Script.findScript("", "db/schema-430to440.sql");
        if (script == null) {
            throw new CloudRuntimeException("Unable to find db/schema-430to440.sql");
        }

        return new File[] { new File(script) };
    }

    @Override
    public void performDataMigration(Connection conn) {
        // TODO Auto-generated method stub

    }

    @Override
    public File[] getCleanupScripts() {
        String script = Script.findScript("", "db/schema-430to440-cleanup.sql");
        if (script == null) {
            throw new CloudRuntimeException("Unable to find db/schema-430to440-cleanup.sql");
        }

        return new File[] { new File(script) };
    }

}
