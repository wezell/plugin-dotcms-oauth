package com.dotcms.osgi.oauth.util;

import java.util.List;
import java.util.Map;
import com.dotcms.rest.api.v1.DotObjectMapperProvider;
import com.dotmarketing.business.DotStateException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

public class JsonUtil {

    final DotObjectMapperProvider mapper = DotObjectMapperProvider.getInstance();
    
    public final Object generate(final String jsonString) throws JsonMappingException, JsonProcessingException {
        if (jsonString == null) {
            throw new DotStateException("jsonString cannot be null");
        }
        


        return jsonString.trim().startsWith("[")
                        ? (List<Map<String, Object>>) mapper.getDefaultObjectMapper().readValue(jsonString, List.class)
                        : (Map<String, Object>) mapper.getDefaultObjectMapper().readValue(jsonString, Map.class);


    }
}
