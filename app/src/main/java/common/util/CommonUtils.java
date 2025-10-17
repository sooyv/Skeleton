package common.util;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CommonUtils {
    public static String convertToSnakeCase(String input) {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (char c : input.toCharArray()) {
            if (Character.isUpperCase(c)) {
                if (!first) {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
            first = false;
        }
        return result.toString();
    }
}
