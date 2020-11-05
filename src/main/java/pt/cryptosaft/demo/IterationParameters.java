package pt.cryptosaft.demo;

import java.util.Deque;
import java.util.LinkedList;

public class IterationParameters {

	private int nextOffset = 0;
	private Deque<String> tree = new LinkedList<String>();
	private boolean elementToCipher = false;

	private int valueStart = 0;
	private int valueEnd = 0;
	private boolean notCiphered = false;
	private int previousElementEnd = 0;
	private int startElementOffset = 0;

	String getCurrentBranch() {
		StringBuffer branch = new StringBuffer();
		getTree().forEach(e -> branch.append(e + "/"));

		return branch.toString();
	}

	int getValueLenght() {
		return this.valueEnd - this.valueStart;
	}

	public int getNextOffset() {
		return nextOffset;
	}

	public void setNextOffset(int nextOffset) {
		this.nextOffset = nextOffset;
	}

	public Deque<String> getTree() {
		return tree;
	}

	public void setTree(Deque<String> tree) {
		this.tree = tree;
	}

	public boolean isElementToCipher() {
		return elementToCipher;
	}

	public void setElementToCipher(boolean elementToCipher) {
		this.elementToCipher = elementToCipher;
	}

	public int getValueStart() {
		return valueStart;
	}

	public void setValueStart(int valueStart) {
		this.valueStart = valueStart;
	}

	public int getValueEnd() {
		return valueEnd;
	}

	public void setValueEnd(int valueEnd) {
		this.valueEnd = valueEnd;
	}

	public boolean isNotCiphered() {
		return notCiphered;
	}

	public void setNotCiphered(boolean notCiphered) {
		this.notCiphered = notCiphered;
	}

	public int getPreviousElementEnd() {
		return previousElementEnd;
	}

	public void setPreviousElementEnd(int previousElementEnd) {
		this.previousElementEnd = previousElementEnd;
	}

	public int getStartElementOffset() {
		return startElementOffset;
	}

	public void setStartElementOffset(int startElementOffset) {
		this.startElementOffset = startElementOffset;
	}

}