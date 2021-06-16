package com.company;

import org.apache.log4j.Logger;

public class MyLogger {
    public static void logger(String s, int select) {
        final Logger logger = org.apache.log4j.Logger.getLogger(Main.class);

        switch (select) {
            case 1:
                logger.debug(s);
                break;
            case 2:
                logger.info(s);
                break;
            case 3:
                logger.warn(s);
                break;
            case 4:
                logger.error(s);
                break;
            case 5:
                logger.fatal(s);
                break;
        }
    }
}
