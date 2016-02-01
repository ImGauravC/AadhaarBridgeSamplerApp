package com.aadhaarconnect.bridge.sampler.util;

import java.lang.reflect.Type;

import android.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class GsonSerializerUtil {
	private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
		public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
			return Base64.decode(json.getAsString(), Base64.NO_WRAP);
		}

		public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(Base64.encodeToString(src, Base64.NO_WRAP));

		}
	}

	public static final Gson customGson = new GsonBuilder().registerTypeHierarchyAdapter(byte[].class,
	        new ByteArrayToBase64TypeAdapter()).create();
	
	
	public static <T extends Object> T unmarshal(String json, Class<T> type) {
		return customGson.fromJson(json, type);
	}
	
	public static <T extends Object> String marshall(T t) {
		return customGson.toJson(t);
	}
}
