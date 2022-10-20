package de.fhg.iosb.iad.ttp;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.beust.jcommander.IStringConverter;

public class ArgsIntRangeParser implements IStringConverter<List<Integer>> {
	@Override
	public List<Integer> convert(String range) {
		List<Integer> result = new LinkedList<Integer>();
		// First, split string by comma
		List<String> s_l = new ArrayList<String>();
		for (String s : range.split(","))
			s_l.add(s.trim());
		// Then iterate ranges and parse them, if necessary
		try {
			for (String s : s_l) {
				if (s.contains("-")) {
					String[] r_l = s.split("-");
					if (r_l.length != 2)
						throw new IllegalArgumentException("Invalid format of PCR range!");
					int begin = Integer.parseInt(r_l[0]);
					int end = Integer.parseInt(r_l[1]);
					for (int i = begin; i <= end; i++)
						result.add(i);
				} else {
					result.add(Integer.parseInt(s));
				}
			}
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Couldn't parse integer value for PCR range!", e);
		}
		return result;
	}
}
